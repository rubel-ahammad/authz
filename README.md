# authz

Cedar-inspired, framework-neutral Kotlin/JVM authorization library (PBAC + ReBAC).

## Usage
```kotlin
val index = PolicyIndex.build(WorkspacePolicies.toSet(), GlobalPolicies.toSet())
val authorizer = PolicyEngineAuthorizer(index)

val decision = authorizer.authorize(
    principal = Principal(workspaceId = "w1", memberId = "m42"),
    action = Action.UPDATE,
    resource = Resource.WORKSPACE,
    context = AuthorizationContext(...)
)
```

## Policy DSL
```kotlin
permit(
    principal = { ... },
    action = { ... },
    resource = { ... }
) `when` { ... } unless { ... }
```

## Semantics
- Forbid overrides permit
- Default deny
