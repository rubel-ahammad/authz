package com.ideascale.authz.context.provider

import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.context.RelationshipContext
import com.ideascale.authz.context.ResourceContext

interface RelationshipContextProvider {
    fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        resourceContext: ResourceContext
    ): RelationshipContext
}
