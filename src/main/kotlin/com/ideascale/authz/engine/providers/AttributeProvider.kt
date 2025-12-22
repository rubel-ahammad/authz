package com.ideascale.authz.engine.providers

import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.AttributeFacts
import com.ideascale.authz.engine.ResourceContext

interface AttributeProvider {
    fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        rc: ResourceContext
    ): AttributeFacts
}
