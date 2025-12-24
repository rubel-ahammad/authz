package com.ideascale.commons.authz

import com.ideascale.commons.authz.decision.Decision
import com.ideascale.commons.authz.resource.ResourceRef
import com.ideascale.commons.authz.action.Action

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
