package com.ideascale.authz.engine

data class ResourceContext(
    val workspaceId: String,
    val communityId: String? = null,
    val campaignId: String? = null,
    val groupId: String? = null
)

data class RelationshipFacts(
    val isWorkspaceMember: Boolean,
    val isIdeaOwner: Boolean = false,
    val isCampaignModerator: Boolean = false,
    val viaGroupIds: Set<String> = emptySet()
)

data class AttributeFacts(
    val memberStatus: String? = null,
    val subscriptionState: String? = null,
    val campaignState: String? = null,
    val ipAllowed: Boolean? = null,
    val emailDomainAllowed: Boolean? = null
)

data class Authorities(
    val workspaceRoles: Set<String> = emptySet(),
    val communityRoles: Set<String> = emptySet(),
    val campaignRoles: Set<String> = emptySet(),
    val groupRoles: Set<String> = emptySet(),
    val permissions: Set<String> = emptySet(),
    val derived: Set<String> = emptySet()
)
