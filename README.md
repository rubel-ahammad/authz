# authz-core

Framework-neutral Kotlin/JVM authorization library implementing Policy-Based Access Control (PBAC) with Relationship-Based Access Control (ReBAC) patterns.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Core Module                              │
│  Subject, Action, ResourceRef, Decision, ReasonCode, Obligation │
│  ActionGroup, EntitySchema, Authorizer interface                 │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                        Engine Module                             │
│  PipelineAuthorizer, Evaluators, Rules, Providers               │
└─────────────────────────────────────────────────────────────────┘
```

## Core Concepts

### Subject (Principal)
```kotlin
data class Subject(
    val workspaceId: String,           // Tenant boundary
    val memberId: String,              // User identifier
    val principalType: PrincipalType,  // USER or SERVICE
    val actorMemberId: String? = null  // For admin impersonation
)
```

### Action
```kotlin
@JvmInline
value class Action(val id: String)  // e.g., "idea.edit", "campaign.launch"
```

Actions are classified into groups via explicit registry:
- `READ` - Query operations
- `WRITE` - Create, edit, update, delete
- `MODERATE` - Hide, unhide, lock, unlock
- `ADMIN` - Ban, unban, invite, launch, close, archive
- `UNKNOWN` - Unregistered actions (denied by default)

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

## Resource Hierarchy

Declared in `EntitySchema`:

```
WORKSPACE (root)
├── COMMUNITY
│   └── CAMPAIGN
│       └── IDEA
├── MEMBER
├── GROUP
└── SUBSCRIPTION

Cross-cutting: TRANSLATION, MODERATION_CASE
```

Query utilities:
```kotlin
EntitySchema.parentOf(ResourceType.IDEA)      // CAMPAIGN
EntitySchema.ancestorsOf(ResourceType.IDEA)   // [CAMPAIGN, COMMUNITY, WORKSPACE]
EntitySchema.isDescendantOf(IDEA, WORKSPACE)  // true
EntitySchema.childrenOf(WORKSPACE)            // [COMMUNITY, MEMBER, GROUP, SUBSCRIPTION]
```

## Authorization Pipeline

The `PipelineAuthorizer` evaluates requests through four stages (deny-first):

```
Request ──► ResourceScopeEvaluator ──► RelationshipEvaluator ──► AttributeEvaluator ──► AuthorityEvaluator ──► Decision
                    │                         │                        │                       │
              Tenant check              Membership check         State constraints        Role/permission
              Scope resolution          Ownership facts          ABAC deny rules          RBAC allow rules
```

### Stage 1: ResourceScopeEvaluator
- Resolves resource context (hierarchy)
- Enforces tenant isolation (`workspaceId` match)
- Applies resource-context deny rules

### Stage 2: RelationshipEvaluator
- Loads relationship facts (membership, ownership)
- Verifies workspace membership
- Applies relationship-based deny rules

### Stage 3: AttributeEvaluator
- Loads attribute facts (subscription, member status, resource state)
- Applies ABAC deny rules:
  - Workspace readonly mode
  - Campaign expired/readonly
  - Idea locked/archived

### Stage 4: AuthorityEvaluator
- Loads authorities (roles, permissions)
- Applies allow rules:
  - Owner can write their resources
  - Campaign moderator can moderate
  - Workspace admin has full access

**Fallback**: `DENY_DEFAULT` if no evaluator allows.

## Providers (Data Loading Interfaces)

Implement these to integrate with your data layer:

```kotlin
interface ResourceContextResolver {
    fun resolve(resource: ResourceRef): ResourceContext
}

interface RelationshipProvider {
    fun load(workspaceId: String, memberId: String, resource: ResourceRef, rc: ResourceContext): RelationshipFacts
}

interface AttributeProvider {
    fun load(...): AttributeFacts
}

interface AuthorityProvider {
    fun load(...): Authorities
}
```

## Rules System

Rules are indexed by `Target` (ResourceType + ActionGroup):

```kotlin
// Deny rule example
DenyRule(
    id = "idea.state.deny_write",
    target = Target(ResourceType.IDEA, ActionGroup.WRITE)
) { ctx ->
    when (ctx.attributeFacts?.idea?.state) {
        IdeaState.LOCKED -> ReasonCode.DENY_IDEA_LOCKED
        IdeaState.ARCHIVED -> ReasonCode.DENY_IDEA_ARCHIVED
        else -> null
    }
}

// Allow rule example
AllowRule(
    id = "idea.write.allow_owner",
    target = Target(ResourceType.IDEA, ActionGroup.WRITE)
) { ctx ->
    if (ctx.relationshipFacts?.isIdeaOwner == true) {
        ctx.allow(ReasonCode.ALLOW_OWNER)
    } else null
}
```

## Action Registry

Actions are explicitly registered in `ActionSemantics`:

```kotlin
ActionSemantics.groupOf(IdeaActions.EDIT)           // WRITE
ActionSemantics.groupOf(IdeaActions.Moderate.HIDE)  // MODERATE
ActionSemantics.groupOf(MemberActions.BAN)          // ADMIN
ActionSemantics.groupOf(Action("typo.action"))      // UNKNOWN (denied)
```

## Usage Example

```kotlin
// 1. Implement providers
val resolver: ResourceContextResolver = MyResourceContextResolver()
val relationshipProvider: RelationshipProvider = MyRelationshipProvider()
val attributeProvider: AttributeProvider = MyAttributeProvider()
val authorityProvider: AuthorityProvider = MyAuthorityProvider()

// 2. Build authorizer
val deps = PipelineDependencies(
    resourceContextResolver = resolver,
    relationshipProvider = relationshipProvider,
    attributeProvider = attributeProvider,
    authorityProvider = authorityProvider
)
val authorizer = PipelineAuthorizerFactory.build(deps)

// 3. Authorize requests
val subject = Subject(workspaceId = "w1", memberId = "m42")
val resource = ResourceRef(ResourceType.IDEA, id = "idea-123")
val context = AuthzContext(requestId = "req-1", ip = "10.0.0.1", channel = Channel.PUBLIC_API)

val decision = authorizer.authorize(subject, IdeaActions.EDIT, resource, context)

if (decision.allowed) {
    // Proceed with action
} else {
    // Handle denial: decision.reason, decision.details
}

// Structured logging
val logFields = decision.toLogFields(subject, IdeaActions.EDIT, resource, context)
```

## Reason Codes

### Deny Codes
| Code | Meaning |
|------|---------|
| `DENY_DEFAULT` | No allow rule matched |
| `DENY_NOT_AUTHENTICATED` | Missing authentication |
| `DENY_TENANT_MISMATCH` | Cross-tenant access attempt |
| `DENY_BANNED` | Member is banned |
| `DENY_PENDING` | Member is pending approval |
| `DENY_NOT_IN_SCOPE` | Not a workspace member |
| `DENY_SUBSCRIPTION_BLOCKED` | Subscription inactive |
| `DENY_IP_RESTRICTED` | IP not allowed |
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
src/main/kotlin/com/ideascale/authz/
├── core/                          # Stable, transport-neutral types
│   ├── Action.kt
│   ├── ActionGroup.kt
│   ├── AuthzContext.kt
│   ├── Authorizer.kt
│   ├── Channel.kt
│   ├── Decision.kt
│   ├── DecisionLogFields.kt
│   ├── Effect.kt
│   ├── EntitySchema.kt            # Declarative resource hierarchy
│   ├── Obligation.kt
│   ├── PrincipalType.kt
│   ├── ReasonCode.kt
│   ├── ResourceRef.kt
│   ├── ResourceType.kt
│   ├── Subject.kt
│   └── actions/
│       ├── ActionSemantics.kt     # Action → ActionGroup registry
│       ├── CampaignActions.kt
│       ├── IdeaActions.kt
│       └── MemberActions.kt
└── engine/                        # Pipeline implementation
    ├── Assembly.kt                # Factory and DI
    ├── AuthzRequest.kt
    ├── EvaluationContext.kt
    ├── Evaluator.kt
    ├── Model.kt                   # Facts and context types
    ├── PipelineAuthorizer.kt
    ├── evaluators/
    │   ├── AttributeEvaluator.kt
    │   ├── AuthorityEvaluator.kt
    │   ├── RelationshipEvaluator.kt
    │   └── ResourceScopeEvaluator.kt
    ├── policies/
    │   ├── PolicyBundle.kt
    │   └── rules/
    │       ├── GlobalRules.kt
    │       └── IdeaRules.kt
    ├── providers/
    │   ├── AttributeProvider.kt
    │   ├── AuthorityProvider.kt
    │   ├── RelationshipProvider.kt
    │   └── ResourceContextResolver.kt
    └── rules/
        └── Rules.kt               # Rule types and registry
```

## Design Principles

1. **Deny-by-default**: Pipeline returns `DENY_DEFAULT` if no allow rule matches
2. **Tenant isolation**: Every request is bound to a `workspaceId`
3. **Framework-neutral**: Core module has zero web/framework dependencies
4. **Explicit action registry**: Unknown actions are denied (typo protection)
5. **Stable contracts**: `ReasonCode` and `ResourceType` are versioned for backward compatibility
6. **Audit-ready**: Every decision has a unique `decisionId` and structured log fields
