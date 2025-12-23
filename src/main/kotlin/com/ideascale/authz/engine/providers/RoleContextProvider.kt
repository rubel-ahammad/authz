package com.ideascale.authz.engine.providers

import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.RelationshipContext
import com.ideascale.authz.engine.ResourceContext
import com.ideascale.authz.engine.RoleContext

interface RoleContextProvider {
    fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        contextFacts: ResourceContext,
        relationshipContext: RelationshipContext
    ): RoleContext
}
