package com.ideascale.authz.engine.providers

import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.RelationshipContext
import com.ideascale.authz.engine.ResourceContext

interface RelationshipContextProvider {
    fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        resourceContext: ResourceContext
    ): RelationshipContext
}
