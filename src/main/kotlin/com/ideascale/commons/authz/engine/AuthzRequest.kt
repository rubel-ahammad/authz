package com.ideascale.commons.authz.engine

import com.ideascale.commons.authz.core.Action
import com.ideascale.commons.authz.core.AuthzContext
import com.ideascale.commons.authz.core.ResourceRef
import com.ideascale.commons.authz.core.Subject

/**
 * Normalized authorization request passed through the pipeline.
 */
data class AuthzRequest(
    val subject: Subject,
    val action: Action,
    val resource: ResourceRef,
    val context: AuthzContext
)
