package com.ideascale.commons.authz.context.provider

import com.ideascale.commons.authz.resource.ResourceRef
import com.ideascale.commons.authz.context.RelationshipContext
import com.ideascale.commons.authz.context.ResourceContext
import com.ideascale.commons.authz.context.RoleContext

interface RoleContextProvider {
    fun load(
        workspaceId: String,
        memberId: String?,
        resource: ResourceRef,
        resourceContext: ResourceContext,
        relationshipContext: RelationshipContext
    ): RoleContext
}
