package com.ideascale.authz.engine.providers

import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.RelationshipFacts
import com.ideascale.authz.engine.ResourceContext

interface RelationshipProvider {
    fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        rc: ResourceContext
    ): RelationshipFacts
}
