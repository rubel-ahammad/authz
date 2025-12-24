package com.ideascale.commons.authz.context.provider

import com.ideascale.commons.authz.core.AuthzContext
import com.ideascale.commons.authz.core.ResourceRef
import com.ideascale.commons.authz.context.AttributeContext
import com.ideascale.commons.authz.context.ResourceContext

interface AttributeContextProvider {
    fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        resourceContext: ResourceContext,
        ctx: AuthzContext
    ): AttributeContext
}
