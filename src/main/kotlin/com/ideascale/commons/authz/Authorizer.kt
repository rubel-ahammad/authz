package com.ideascale.commons.authz

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.decision.Decision
import com.ideascale.commons.authz.resource.Resource

/**
 * Transport-neutral authorization interface.
 *
 * Put framework-specific helpers (Spring/Ktor filters, exceptions, etc.)
 * in separate modules (e.g., authz-spring, authz-ktor).
 *
 * Usage:
 * ```kotlin
 * val context = AuthorizationContext(
 *     principal = PrincipalContext(...),
 *     resource = ResourceContext(...),
 *     environment = EnvironmentContext(...)
 * )
 * val decision = authorizer.authorize(principal, action, resource, context)
 * ```
 */
interface Authorizer {
    fun authorize(
        principal: Principal,
        action: Action,
        resource: Resource,
        context: AuthorizationContext = AuthorizationContext.anonymous()
    ): Decision
}
