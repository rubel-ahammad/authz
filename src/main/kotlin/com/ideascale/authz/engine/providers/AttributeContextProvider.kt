package com.ideascale.authz.engine.providers

import com.ideascale.authz.core.AuthzContext
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.AttributeContext
import com.ideascale.authz.engine.ResourceContext

interface AttributeContextProvider {
    fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        contextFacts: ResourceContext,
        ctx: AuthzContext
    ): AttributeContext
}
