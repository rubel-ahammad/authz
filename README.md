# authz

Framework-neutral Kotlin/JVM authorization library implementing Policy-Based Access Control (PBAC) with Relationship-Based Access Control (ReBAC) patterns.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Core Module                              │
│  Subject, Action, ResourceRef, Decision, ReasonCode, Obligation │
│  ActionGroup, ResourceHierarchy, Authorizer interface            │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                        Engine Module                             │
│  PipelineAuthorizer, EvaluationSteps, Rules, Providers          │
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

Declared in `ResourceHierarchy`:

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
ResourceHierarchy.parentOf(ResourceType.IDEA)      // CAMPAIGN
ResourceHierarchy.ancestorsOf(ResourceType.IDEA)   // [CAMPAIGN, COMMUNITY, WORKSPACE]
ResourceHierarchy.isDescendantOf(IDEA, WORKSPACE)  // true
ResourceHierarchy.childrenOf(WORKSPACE)            // [COMMUNITY, MEMBER, GROUP, SUBSCRIPTION]
```

## Authorization Pipeline

The `PipelineAuthorizer` evaluates requests through four steps (deny-first):

```
Request ──► ResourceContextStep ──► RelationshipStep ──► AttributeStep ──► RoleStep ──► Decision
                    │                      │                   │                 │
              Tenant check           Relationship facts  State constraints   Role-based
              Context resolution     Ownership facts     ABAC deny rules     allow rules
```

### Step 1: ResourceEvaluationStep
- Loads resource context facts (hierarchy context)
- Enforces tenant isolation (`workspaceId` match)
- Applies resource-context deny rules

### Step 2: RelationshipEvaluationStep
- Loads relationship facts (ownership, group links)
- Applies relationship-based deny rules

### Step 3: AttributeEvaluationStep
- Loads attribute facts (subscription, member status, resource state)
- Applies ABAC deny rules:
  - Workspace readonly mode
  - Campaign expired/readonly
  - Idea locked/archived

### Step 4: RoleEvaluationStep
- Loads role facts (workspace/community/campaign/group roles)
- Applies allow rules:
  - Owner can write their resources
  - Campaign moderator can moderate
  - Workspace admin has full access

**Fallback**: `DENY_DEFAULT` if no step allows.

## Facts Model

The pipeline collects four types of facts:

```kotlin
// Step 1: Resource context in the hierarchy
sealed interface ResourceContext {
    val workspaceId: String
}
data class IdeaContext(workspaceId, communityId, campaignId, ideaId)

// Step 2: Subject's relationships to the resource
data class RelationshipContext(
    val isIdeaOwner: Boolean,
    val viaGroupIds: Set<String>
)

// Step 3: State and configuration attributes
data class AttributeContext(
    val workspace: WorkspaceAttrs,
    val member: MemberAttrs,
    val campaign: CampaignAttrs?,
    val idea: IdeaAttrs?
)

// Step 4: Role assignments
data class RoleContext(
    val workspaceRoles: Set<RoleId>,
    val communityRoles: Set<RoleId>,
    val campaignRoles: Set<RoleId>,
    val groupRoles: Set<RoleId>
)
```

## Providers (Data Loading Interfaces)

Implement these to integrate with your data layer:

```kotlin
interface ResourceContextProvider {
    fun load(resource: ResourceRef): ResourceContext
}

interface RelationshipContextProvider {
    fun load(workspaceId: String, memberId: String?, resource: ResourceRef, resourceContext: ResourceContext): RelationshipContext
}

interface AttributeContextProvider {
    fun load(workspaceId: String, memberId: String?, resource: ResourceRef, resourceContext: ResourceContext, ctx: AuthzContext): AttributeContext
}

interface RoleContextProvider {
    fun load(workspaceId: String, memberId: String?, resource: ResourceRef, resourceContext: ResourceContext, relationshipContext: RelationshipContext): RoleContext
}
```

## Rules System

Rules are indexed by `Target` (ResourceType + ActionGroup):

```kotlin
// Deny rule example
deny {
    id("idea.state.deny_write")
    target(ResourceType.IDEA, ActionGroup.WRITE)
    condition { ctx ->
        when (ctx.attributeContext?.idea?.state) {
            IdeaState.LOCKED -> ReasonCode.DENY_IDEA_LOCKED
            IdeaState.ARCHIVED -> ReasonCode.DENY_IDEA_ARCHIVED
            else -> null
        }
    }
}

// Allow rule example
allow {
    id("idea.write.allow_owner")
    target(ResourceType.IDEA, ActionGroup.WRITE)
    condition { ctx ->
        if (ctx.relationshipContext?.isIdeaOwner == true) {
            ctx.allow(ReasonCode.ALLOW_OWNER)
        } else null
    }
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
val resourceContextProvider: ResourceContextProvider = MyResourceContextProvider()
val relationshipContextProvider: RelationshipContextProvider = MyRelationshipContextProvider()
val attributeContextProvider: AttributeContextProvider = MyAttributeContextProvider()
val roleContextProvider: RoleContextProvider = MyRoleContextProvider()

// 2. Build authorizer
val deps = PipelineDependencies(
    resourceContextProvider = resourceContextProvider,
    relationshipContextProvider = relationshipContextProvider,
    attributeContextProvider = attributeContextProvider,
    roleContextProvider = roleContextProvider
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
│   ├── ResourceHierarchy.kt       # Declarative resource hierarchy
│   ├── Obligation.kt
│   ├── PrincipalType.kt
│   ├── ReasonCode.kt
│   ├── ResourceRef.kt
│   ├── ResourceType.kt
│   ├── Subject.kt
│   └── action/
│       ├── ActionSemantics.kt     # Action → ActionGroup registry
│       ├── CampaignActions.kt
│       ├── IdeaActions.kt
│       └── MemberActions.kt
├── context/                       # Evaluation context models
│   ├── Model.kt                   # Resource/Relationship/Attribute/Role context types
│   └── provider/
│       ├── AttributeContextProvider.kt
│       ├── RoleContextProvider.kt
│       ├── RelationshipContextProvider.kt
│       └── ResourceContextProvider.kt
├── engine/                        # Pipeline implementation
    ├── Assembly.kt                # Factory and DI
    ├── AuthzRequest.kt
    ├── EvaluationContext.kt
    ├── EvaluationStep.kt          # EvaluationStep interface, StepResult
    ├── PipelineAuthorizer.kt
    ├── evaluator/
    │   ├── AttributeEvaluationStep.kt
    │   ├── RoleEvaluationStep.kt
    │   ├── RelationshipEvaluationStep.kt
    │   └── ResourceEvaluationStep.kt
└── policy/                        # Rule DSL and default policies
    ├── PolicyBundle.kt
    ├── default/
    │   ├── GlobalRules.kt
    │   └── IdeaRules.kt
    ├── dsl/
    │   └── RuleDsl.kt
    └── rule/
        └── Rules.kt               # Rule types and registry
```

## Design Principles

1. **Deny-by-default**: Pipeline returns `DENY_DEFAULT` if no allow rule matches
2. **Tenant isolation**: Every request is bound to a `workspaceId`
3. **Framework-neutral**: Core module has zero web/framework dependencies
4. **Explicit action registry**: Unknown actions are denied (typo protection)
5. **Stable contracts**: `ReasonCode` and `ResourceType` are versioned for backward compatibility
6. **Audit-ready**: Every decision has a unique `decisionId` and structured log fields
