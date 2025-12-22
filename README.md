# authz-core

Framework-neutral Kotlin/JVM library that defines authorization contract types for PBAC/ReBAC-style authorization.

## What it provides
- Canonical `Action` identifiers (e.g., `idea.edit`, `campaign.launch`)
- Stable `ResourceType` + `ResourceRef`
- `Subject` (tenant = workspaceId, user = memberId, optional actorMemberId for impersonation)
- `AuthzContext` (request context signals)
- `Decision` with `Effect`, `ReasonCode`, and optional `Obligation`s
- `Authorizer` interface (transport-neutral)
- Logging helper: `Decision.toLogFields(...)`
- Example action catalogs and tests enforcing naming conventions

## Example usage
```kotlin
import com.ideascale.authz.core.*
import com.ideascale.authz.core.actions.IdeaActions

val subject = Subject(workspaceId = "w1", memberId = "m42")
val resource = ResourceRef(ResourceType.IDEA, id = "idea-123")
val ctx = AuthzContext(requestId = "req-1", ip = "10.0.0.1", channel = Channel.PUBLIC_API)

val authorizer: Authorizer = object : Authorizer {
    override fun authorize(subject: Subject, action: Action, resource: ResourceRef, context: AuthzContext): Decision {
        return Decision.deny(ReasonCode.DENY_DEFAULT)
    }
}

val decision = authorizer.authorize(subject, IdeaActions.EDIT, resource, ctx)
println(decision.allowed)
println(decision.toLogFields(subject, IdeaActions.EDIT, resource, ctx))
```
