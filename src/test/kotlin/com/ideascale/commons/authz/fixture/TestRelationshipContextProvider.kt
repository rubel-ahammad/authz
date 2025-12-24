package com.ideascale.commons.authz.fixture

import com.ideascale.commons.authz.context.RelationshipContext
import com.ideascale.commons.authz.context.ResourceContext
import com.ideascale.commons.authz.context.provider.RelationshipContextProvider
import com.ideascale.commons.authz.resource.ResourceRef

class TestRelationshipContextProvider(
    private val ideaOwners: Map<String, String> = emptyMap(),
    private val defaultContext: RelationshipContext = RelationshipContext()
) : RelationshipContextProvider {

    override fun load(
        workspaceId: String,
        memberId: String?,
        resource: ResourceRef,
        resourceContext: ResourceContext
    ): RelationshipContext {
        // Check if member is owner of the resource
        if (memberId != null && ideaOwners[resource.id] == memberId) {
            return RelationshipContext(isIdeaOwner = true)
        }

        return defaultContext
    }

    class Builder {
        private val ideaOwners = mutableMapOf<String, String>()

        fun withIdeaOwner(memberId: String, ideaId: String) = apply {
            ideaOwners[ideaId] = memberId
        }

        fun build(): TestRelationshipContextProvider = TestRelationshipContextProvider(
            ideaOwners = ideaOwners.toMap()
        )
    }

    companion object {
        fun builder() = Builder()

        fun withIdeaOwner(memberId: String, ideaId: String): TestRelationshipContextProvider {
            return TestRelationshipContextProvider(
                ideaOwners = mapOf(ideaId to memberId)
            )
        }

        fun default(): TestRelationshipContextProvider {
            return TestRelationshipContextProvider()
        }
    }
}
