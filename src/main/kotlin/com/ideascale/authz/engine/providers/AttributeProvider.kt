package com.ideascale.authz.engine.providers

import com.ideascale.authz.core.AuthzContext
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.AttributeFacts
import com.ideascale.authz.engine.ResourceContextFacts

interface AttributeProvider {
    fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        contextFacts: ResourceContextFacts,
        ctx: AuthzContext
    ): AttributeFacts
}
