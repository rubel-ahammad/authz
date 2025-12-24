package com.ideascale.commons.authz.fixture

import com.ideascale.commons.authz.context.RelationshipContext
import com.ideascale.commons.authz.context.ResourceContext
import com.ideascale.commons.authz.context.RoleContext
import com.ideascale.commons.authz.context.RoleIds
import com.ideascale.commons.authz.context.provider.RoleContextProvider
import com.ideascale.commons.authz.core.ResourceRef

class TestRoleContextProvider private constructor(
    private val workspaceAdmins: Set<String>,
    private val workspaceMembers: Set<String>,
    private val communityAdmins: Map<String, Set<String>>,
    private val campaignAdmins: Map<String, Set<String>>
) : RoleContextProvider {

    override fun load(
        workspaceId: String,
        memberId: String?,
        resource: ResourceRef,
        resourceContext: ResourceContext,
        relationshipContext: RelationshipContext
    ): RoleContext {
        // Anonymous users get ANONYMOUS role
        if (memberId == null) {
            return RoleContext(
                workspaceRoles = setOf(RoleIds.ANONYMOUS)
            )
        }

        // Build workspace roles
        val workspaceRoles = buildSet {
            if (memberId in workspaceAdmins) {
                add(RoleIds.WORKSPACE_ADMIN)
                add(RoleIds.WORKSPACE_MEMBER) // Admins are also members
            }
            if (memberId in workspaceMembers) {
                add(RoleIds.WORKSPACE_MEMBER)
            }
        }

        // Build community roles based on resource context
        val communityRoles = buildSet {
            val communityId = extractCommunityId(resourceContext)
            if (communityId != null && memberId in (communityAdmins[communityId] ?: emptySet())) {
                add(RoleIds.ADMIN)
            }
        }

        // Build campaign roles based on resource context
        val campaignRoles = buildSet {
            val campaignId = extractCampaignId(resourceContext)
            if (campaignId != null && memberId in (campaignAdmins[campaignId] ?: emptySet())) {
                add(RoleIds.ADMIN)
            }
        }

        return RoleContext(
            workspaceRoles = workspaceRoles,
            communityRoles = communityRoles,
            campaignRoles = campaignRoles
        )
    }

    private fun extractCommunityId(resourceContext: ResourceContext): String? {
        return when (resourceContext) {
            is com.ideascale.commons.authz.context.CommunityContext -> resourceContext.communityId
            is com.ideascale.commons.authz.context.CampaignContext -> resourceContext.communityId
            is com.ideascale.commons.authz.context.IdeaContext -> resourceContext.communityId
            else -> null
        }
    }

    private fun extractCampaignId(resourceContext: ResourceContext): String? {
        return when (resourceContext) {
            is com.ideascale.commons.authz.context.CampaignContext -> resourceContext.campaignId
            is com.ideascale.commons.authz.context.IdeaContext -> resourceContext.campaignId
            else -> null
        }
    }

    class Builder {
        private val workspaceAdmins = mutableSetOf<String>()
        private val workspaceMembers = mutableSetOf<String>()
        private val communityAdmins = mutableMapOf<String, MutableSet<String>>()
        private val campaignAdmins = mutableMapOf<String, MutableSet<String>>()

        fun withWorkspaceAdmin(memberId: String) = apply {
            workspaceAdmins.add(memberId)
        }

        fun withWorkspaceMember(memberId: String) = apply {
            workspaceMembers.add(memberId)
        }

        fun withCommunityAdmin(communityId: String, memberId: String) = apply {
            communityAdmins.getOrPut(communityId) { mutableSetOf() }.add(memberId)
        }

        fun withCampaignAdmin(campaignId: String, memberId: String) = apply {
            campaignAdmins.getOrPut(campaignId) { mutableSetOf() }.add(memberId)
        }

        fun build(): TestRoleContextProvider = TestRoleContextProvider(
            workspaceAdmins = workspaceAdmins.toSet(),
            workspaceMembers = workspaceMembers.toSet(),
            communityAdmins = communityAdmins.mapValues { it.value.toSet() },
            campaignAdmins = campaignAdmins.mapValues { it.value.toSet() }
        )
    }

    companion object {
        fun builder() = Builder()
    }
}
