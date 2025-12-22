package com.ideascale.authz.core

/**
 * Transport-neutral authorization interface.
 *
 * Put framework-specific helpers (Spring/Ktor filters, exceptions, etc.)
 * in separate modules (e.g., authz-spring, authz-ktor).
 */
interface Authorizer {
    fun authorize(
        subject: Subject,
        action: Action,
        resource: ResourceRef,
        context: AuthzContext = AuthzContext()
    ): Decision
}
