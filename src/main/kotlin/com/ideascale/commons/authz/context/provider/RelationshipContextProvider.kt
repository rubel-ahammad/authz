package com.ideascale.commons.authz.context.provider

import com.ideascale.commons.authz.core.ResourceRef
import com.ideascale.commons.authz.context.RelationshipContext
import com.ideascale.commons.authz.context.ResourceContext

interface RelationshipContextProvider {
    fun load(
        workspaceId: String,
        memberId: String?,
        resource: ResourceRef,
        resourceContext: ResourceContext
    ): RelationshipContext
}
