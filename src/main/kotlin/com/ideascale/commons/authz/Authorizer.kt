package com.ideascale.commons.authz

import com.ideascale.commons.authz.decision.Decision
import com.ideascale.commons.authz.resource.ResourceRef
import com.ideascale.commons.authz.action.Action

/**
 * Transport-neutral authorization interface.
 *
 * Put framework-specific helpers (Spring/Ktor filters, exceptions, etc.)
 * in separate modules (e.g., authz-spring, authz-ktor).
 *
 * Usage:
 * ```kotlin
 * val context = AuthorizationContext(
 *     roles = RoleContext(...),
 *     relationships = RelationshipContext(...),
 *     attributes = AttributeContext(...)
 * )
 * val decision = authorizer.authorize(subject, action, resource, context)
 * ```
 */
interface Authorizer {
    fun authorize(
        subject: Subject,
        action: Action,
        resource: ResourceRef,
        context: AuthorizationContext = AuthorizationContext()
    ): Decision
}
