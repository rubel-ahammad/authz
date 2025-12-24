package com.ideascale.commons.authz.context

sealed interface ResourceContext {
    val workspaceId: String
}

data class WorkspaceContext(
    override val workspaceId: String
) : ResourceContext

data class CommunityContext(
    override val workspaceId: String,
    val communityId: String
) : ResourceContext

data class CampaignContext(
    override val workspaceId: String,
    val communityId: String,
    val campaignId: String
) : ResourceContext

data class IdeaContext(
    override val workspaceId: String,
    val communityId: String,
    val campaignId: String,
    val ideaId: String
) : ResourceContext

data class MemberContext(
    override val workspaceId: String,
    val memberId: String
) : ResourceContext
