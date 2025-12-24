package com.ideascale.commons.authz

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.AuthzContext
import com.ideascale.commons.authz.resource.ResourceRef
import com.ideascale.commons.authz.Subject

/**
 * Normalized authorization request passed through the pipeline.
 */
data class AuthzRequest(
    val subject: Subject,
    val action: Action,
    val resource: ResourceRef,
    val context: AuthzContext
)
