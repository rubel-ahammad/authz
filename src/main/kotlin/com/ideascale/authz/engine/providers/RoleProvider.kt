package com.ideascale.authz.engine.providers

import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.RelationshipFacts
import com.ideascale.authz.engine.ResourceContextFacts
import com.ideascale.authz.engine.RoleFacts

interface RoleProvider {
    fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        contextFacts: ResourceContextFacts,
        relationshipFacts: RelationshipFacts
    ): RoleFacts
}
