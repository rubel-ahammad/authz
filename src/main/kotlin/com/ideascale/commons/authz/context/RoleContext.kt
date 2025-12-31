package com.ideascale.commons.authz.context

/**
 * Canonical role identifiers recognized by the authorization engine.
 */
enum class Role {
    WORKSPACE_ADMIN,
    WORKSPACE_MEMBER,
    CAMPAIGN_MODERATOR,
    COMMUNITY_MEMBER,
    ANONYMOUS,
    ADMIN
}

data class RoleContext(
    val workspaceRoles: Set<Role> = emptySet(),
    val communityRoles: Set<Role> = emptySet(),
    val campaignRoles: Set<Role> = emptySet(),
    val groupRoles: Set<Role> = emptySet()
)
