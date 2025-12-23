package com.ideascale.authz.context.provider

import com.ideascale.authz.core.AuthzContext
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.context.AttributeContext
import com.ideascale.authz.context.ResourceContext

interface AttributeContextProvider {
    fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        resourceContext: ResourceContext,
        ctx: AuthzContext
    ): AttributeContext
}
