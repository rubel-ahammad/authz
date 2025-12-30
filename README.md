# authz

Framework-neutral Kotlin/JVM authorization library implementing a Cedar-inspired Policy-Based Access Control (PBAC) with support for Relationship-Based Access Control (ReBAC) patterns.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Core Module                              │
│  Subject, Action, ResourceRef, Decision, ReasonCode, Obligation │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                     Policy Engine Module                         │
│  PolicyEngineAuthorizer, PolicyEvaluator, PolicyIndex           │
│  Cedar-style DSL: permit(), forbid(), when, unless              │
└─────────────────────────────────────────────────────────────────┘
```

## Core Concepts

### Subject (Principal)
```kotlin
data class Subject(
    val workspaceId: String,           // Tenant boundary
    val memberId: String?,             // User identifier (null for anonymous)
    val principalType: PrincipalType,  // USER or SERVICE
    val actorMemberId: String? = null  // For admin impersonation
)
```

### Action
```kotlin
@JvmInline
value class Action(val id: String) : ActionItem  // e.g., "idea.edit", "idea.moderate.lock"
```

Actions are organized hierarchically using `HierarchicalActionGroup`:
```kotlin
object IdeaActionsHierarchy : HierarchicalActionGroup("idea") {
    val view = action("idea.view")
    val edit = action("idea.edit")
    val delete = action("idea.delete")

    val readActions = group("idea.read", view, list)
    val writeActions = group("idea.write", create, edit, delete)
}
```

### Resource
```kotlin
data class ResourceRef(
    val type: ResourceType,  // WORKSPACE, COMMUNITY, CAMPAIGN, IDEA, MEMBER, etc.
    val id: String
)
```

### Decision
```kotlin
data class Decision(
    val effect: Effect,              // ALLOW or DENY
    val reason: ReasonCode,          // Stable audit code
    val obligations: Set<Obligation>, // Post-decision requirements
    val decisionId: String,          // Unique ID for tracing
    val details: Map<String, String> // Additional context
)
```

## Policy DSL

The library uses a Cedar-inspired DSL for defining authorization policies.

### Policy Structure
```
permit|forbid (
    principal = { ... },
    action = { ... },
    resource = { ... }
) when { ... } unless { ... }
```

### Permit Policies

**Role-based (Membership) Permission:**
```kotlin
permit(
    principal = { hasRole(RoleIds.WORKSPACE_ADMIN, at = RoleLevel.WORKSPACE) },
    action = { `in`(IdeaActionsHierarchy) },
    resource = { any() }
).id("idea.admin.full_access")
 .reason(ReasonCode.ALLOW_ROLE)
```

**Relationship-based Permission (Ownership):**
```kotlin
(permit(
    principal = { authenticated() },
    action = { eq(IdeaActionsHierarchy.edit) },
    resource = { any() }
) `when` {
    relationship { isIdeaOwner() }
}).id("idea.owner.edit")
  .reason(ReasonCode.ALLOW_OWNER)
```

**Relationship-based Permission (Group):**
```kotlin
(permit(
    principal = { authenticated() },
    action = { `in`(IdeaActionsHierarchy.readActions) },
    resource = { any() }
) `when` {
    relationship { inAnyGroup() }
}).id("idea.group.view")
  .reason(ReasonCode.ALLOW_RELATIONSHIP)
```

### Forbid Policies

**Attribute-based Deny:**
```kotlin
(forbid(
    principal = { any() },
    action = { `in`(IdeaActionsHierarchy.writeActions) },
    resource = { any() }
) `when` {
    attribute { ideaState(IdeaState.LOCKED) }
}).id("idea.locked.deny_write")
  .reason(ReasonCode.DENY_IDEA_LOCKED)
```

**With Exception (unless):**
```kotlin
(forbid(
    principal = { any() },
    action = { `in`(IdeaActionsHierarchy.writeActions) },
    resource = { any() }
) `when` {
    attribute { ideaState(IdeaState.LOCKED) }
} unless {
    role { hasRole(RoleIds.CAMPAIGN_MODERATOR, at = RoleLevel.CAMPAIGN) }
}).id("idea.locked.deny_write")
  .reason(ReasonCode.DENY_IDEA_LOCKED)
```

## Evaluation Semantics

Following Cedar's evaluation model:

1. **Find applicable policies** - Match request against policy scopes
2. **Evaluate conditions** - Check `when` and `unless` clauses
3. **Forbid overrides permit** - If ANY forbid policy matches → DENY
4. **Permit if matched** - If ANY permit policy matches → ALLOW
5. **Default deny** - No matching policy → DENY

## Policy Organization

Policies are organized by resource type using `PolicySetBase`:

```kotlin
object IdeaPolicies : PolicySetBase(ResourceType.IDEA) {
    val adminFullAccess: Policy = policy(
        permit(
            principal = { hasRole(RoleIds.WORKSPACE_ADMIN, at = RoleLevel.WORKSPACE) },
            action = { `in`(IdeaActionsHierarchy) },
            resource = { any() }
        ).id("idea.admin.full_access")
         .reason(ReasonCode.ALLOW_ROLE)
    )

    // ... more policies
}
```

## Policy Index

For efficient evaluation, policies are indexed at startup:

```kotlin
// Build index once at startup
val index = PolicyIndex.build(
    IdeaPolicies.toSet(),
    GlobalPolicies.toSet()
)

// Create authorizer with pre-built index
val authorizer = PolicyEngineAuthorizer(index)
```

The index provides O(1) lookup by resource type instead of scanning all policies.

## Usage Example

```kotlin
// 1. Build policy index at startup
val index = PolicyIndex.build(
    IdeaPolicies.toSet(),
    GlobalPolicies.toSet()
)

// 2. Create authorizer (stateless, no I/O)
val authorizer = PolicyEngineAuthorizer(index)

// 3. Build context with whatever data you have
val context = AuthorizationContext(
    requestId = "req-1",
    roles = RoleContext(
        workspaceRoles = setOf(RoleId("member")),
        communityRoles = emptySet(),
        campaignRoles = emptySet(),
        groupRoles = emptySet()
    ),
    relationships = RelationshipContext(
        isIdeaOwner = true,
        viaGroupIds = emptySet()
    ),
    attributes = AttributeContext(
        workspace = WorkspaceAttrs(...),
        member = MemberAttrs(...),
        campaign = CampaignAttrs(...),
        idea = IdeaAttrs(state = IdeaState.ACTIVE)
    )
)

// 4. Authorize
val subject = Subject(workspaceId = "w1", memberId = "m42")
val resource = ResourceRef(ResourceType.IDEA, id = "idea-123")

val decision = authorizer.authorize(
    subject = subject,
    action = IdeaActionsHierarchy.edit,
    resource = resource,
    context = context
)

if (decision.allowed) {
    // Proceed with action
} else {
    // Handle denial: decision.reason, decision.details
}
```

## Flexible Context Building

All context fields are optional. Pass only what's needed:

```kotlin
// Minimal context (only roles)
val context = AuthorizationContext(
    roles = RoleContext(workspaceRoles = setOf(RoleId("admin")), ...)
)

// Using builder pattern
val context = AuthorizationContext.builder()
    .requestId("req-123")
    .roles(roleContext)
    .relationships(relationshipContext)
    .build()
```

Policies gracefully handle missing context - conditions that need unavailable context evaluate to `false`.

## Reason Codes

### Deny Codes
| Code | Meaning |
|------|---------|
| `DENY_DEFAULT` | No permit policy matched |
| `DENY_NOT_AUTHENTICATED` | Missing authentication |
| `DENY_TENANT_MISMATCH` | Cross-tenant access attempt |
| `DENY_BANNED` | Member is banned |
| `DENY_PENDING` | Member is pending approval |
| `DENY_NOT_IN_SCOPE` | Not a workspace member |
| `DENY_WORKSPACE_READONLY` | Workspace in readonly mode |
| `DENY_CAMPAIGN_EXPIRED` | Campaign has expired |
| `DENY_IDEA_LOCKED` | Idea is locked |
| `DENY_IDEA_ARCHIVED` | Idea is archived |

### Allow Codes
| Code | Meaning |
|------|---------|
| `ALLOW_ROLE` | Granted via role assignment |
| `ALLOW_OWNER` | Resource owner |
| `ALLOW_RELATIONSHIP` | Via relationship (group, etc.) |
| `ALLOW_SYSTEM` | System/service principal |

## Project Structure

```
src/main/kotlin/com/ideascale/commons/authz/
├── Authorizer.kt                    # Authorizer interface
├── AuthorizationContext.kt          # Context for authorization (roles, relationships, etc.)
├── Subject.kt                       # Principal/subject model
├── action/
│   ├── Action.kt                    # Action value class
│   ├── ActionHierarchy.kt           # HierarchicalActionGroup
│   └── ActionMatcher.kt             # Action matching utilities
├── context/
│   ├── AttributeContext.kt          # Attribute facts (workspace, member, campaign, idea state)
│   ├── RelationshipContext.kt       # Relationship facts (ownership, groups)
│   ├── ResourceContext.kt           # Resource hierarchy context
│   └── RoleContext.kt               # Role assignments
├── decision/
│   ├── Decision.kt                  # Authorization decision
│   ├── Effect.kt                    # ALLOW/DENY
│   ├── Obligation.kt                # Post-decision requirements
│   └── ReasonCode.kt                # Audit codes
├── engine/
│   ├── PolicyEngineAuthorizer.kt    # Main authorizer (stateless, no I/O)
│   ├── catalog/
│   │   ├── GlobalPolicies.kt        # Global deny policies
│   │   ├── IdeaActionsHierarchy.kt  # Idea action definitions
│   │   └── IdeaPolicies.kt          # Idea policies
│   ├── dsl/
│   │   ├── ConditionBuilders.kt     # when/unless condition DSL
│   │   ├── PolicyDsl.kt             # permit()/forbid() DSL
│   │   ├── PolicySetDsl.kt          # PolicySetBase
│   │   └── ScopeBuilders.kt         # Principal/Action/Resource scope DSL
│   ├── eval/
│   │   ├── PolicyEvaluator.kt       # Policy evaluation engine
│   │   ├── PolicyIndex.kt           # Efficient policy lookup
│   │   └── ScopeMatcher.kt          # Scope matching logic
│   └── model/
│       ├── Condition.kt             # Policy conditions
│       ├── Policy.kt                # Policy model
│       ├── PolicyEffect.kt          # PERMIT/FORBID
│       ├── PolicySet.kt             # Policy container
│       └── Scope.kt                 # Principal/Action/Resource scopes
└── resource/
    ├── ResourceRef.kt               # Resource reference
    └── ResourceType.kt              # Resource type enum
```

## Design Principles

1. **Cedar-inspired semantics**: Forbid overrides permit, default deny
2. **Declarative policies**: Policies defined in code using type-safe DSL
3. **Efficient evaluation**: Index-based policy lookup for O(1) access
4. **Stateless & no I/O**: Pure evaluation, caller provides all context
5. **Microservice ready**: Can be extracted to separate auth service
6. **Tenant isolation**: Every request is bound to a `workspaceId`
7. **Framework-neutral**: Zero web/framework dependencies in core
8. **Audit-ready**: Every decision has a unique `decisionId` and structured log fields
9. **Hierarchical actions**: Support for `action in ActionGroup` matching
