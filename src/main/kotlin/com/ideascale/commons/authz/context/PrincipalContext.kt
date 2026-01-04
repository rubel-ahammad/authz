package com.ideascale.commons.authz.context

import com.ideascale.commons.authz.resource.Resource

/**
 * Principal context containing both attributes (ABAC) and roles (Membership Pattern).
 *
 * This follows Cedar's membership pattern where permissions are derived from
 * the principal's membership in groups/roles.
 *
 * Roles are scoped by resource ID:
 * - A principal can be admin of ONE workspace (enforced by workspaceRole)
 * - A principal can be admin of MULTIPLE communities/campaigns
 * - A principal can be moderator of MULTIPLE resources (independently)
 */
data class PrincipalContext(
    // === ATTRIBUTES (ABAC) ===
    val status: MemberStatus = MemberStatus.ACTIVE,
    val email: String? = null,
    val emailDomain: String? = null,

    // === ROLES (Membership Pattern) ===

    // Workspace-level role (can be admin of ONLY ONE workspace)
    val workspaceRole: WorkspaceRole = WorkspaceRole.MEMBER,

    // Admin roles (can admin MULTIPLE communities/campaigns)
    val communityAdmin: Set<Long> = emptySet(),
    val campaignAdmin: Set<Long> = emptySet(),

    // Moderator roles (can moderate MULTIPLE, independently)
    val communityModerator: Set<Long> = emptySet(),
    val campaignModerator: Set<Long> = emptySet(),
    val groupModerator: Set<Long> = emptySet(),
    val customFieldModerator: Set<Long> = emptySet()
) {
    // === WORKSPACE ROLE CHECKS ===

    fun isWorkspaceAdmin(): Boolean = workspaceRole == WorkspaceRole.ADMIN
    fun isWorkspaceMember(): Boolean = workspaceRole == WorkspaceRole.MEMBER || isWorkspaceAdmin()

    // === ADMIN ROLE CHECKS ===

    fun isCommunityAdmin(communityId: Long): Boolean = communityAdmin.contains(communityId)
    fun isCampaignAdmin(campaignId: Long): Boolean = campaignAdmin.contains(campaignId)

    // === MODERATOR ROLE CHECKS ===

    fun isCommunityModerator(communityId: Long): Boolean = communityModerator.contains(communityId)
    fun isCampaignModerator(campaignId: Long): Boolean = campaignModerator.contains(campaignId)
    fun isGroupModerator(groupId: Long): Boolean = groupModerator.contains(groupId)
    fun isCustomFieldModerator(fieldId: Long): Boolean = customFieldModerator.contains(fieldId)

    // === CONVENIENCE METHODS ===

    /**
     * Check if principal has admin role for any resource type.
     */
    fun isAdminOf(resourceType: Resource, resourceId: Long): Boolean = when (resourceType) {
        Resource.WORKSPACE -> isWorkspaceAdmin()
        Resource.COMMUNITY -> isCommunityAdmin(resourceId)
        Resource.CAMPAIGN -> isCampaignAdmin(resourceId)
        else -> false
    }

    /**
     * Check if principal has moderator role for any resource type.
     */
    fun isModeratorOf(resourceType: Resource, resourceId: Long): Boolean = when (resourceType) {
        Resource.COMMUNITY -> isCommunityModerator(resourceId)
        Resource.CAMPAIGN -> isCampaignModerator(resourceId)
        Resource.GROUP -> isGroupModerator(resourceId)
        Resource.CUSTOM_FIELD -> isCustomFieldModerator(resourceId)
        else -> false
    }

    /**
     * Check if principal has admin OR moderator role for a resource.
     */
    fun hasManagementRoleFor(resourceType: Resource, resourceId: Long): Boolean =
        isAdminOf(resourceType, resourceId) || isModeratorOf(resourceType, resourceId)

    companion object {
        /**
         * Context for anonymous users - no roles, active status.
         */
        val ANONYMOUS = PrincipalContext(
            status = MemberStatus.ACTIVE,
            workspaceRole = WorkspaceRole.MEMBER
        )

        /**
         * Context for banned users.
         */
        val BANNED = PrincipalContext(
            status = MemberStatus.BANNED,
            workspaceRole = WorkspaceRole.MEMBER
        )
    }
}
