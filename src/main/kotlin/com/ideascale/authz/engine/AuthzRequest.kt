package com.ideascale.authz.engine

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.AuthzContext
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.core.Subject

/**
 * Normalized authorization request passed through the pipeline.
 */
data class AuthzRequest(
    val subject: Subject,
    val action: Action,
    val resource: ResourceRef,
    val context: AuthzContext
)
