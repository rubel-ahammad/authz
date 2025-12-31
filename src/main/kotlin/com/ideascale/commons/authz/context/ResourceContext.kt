package com.ideascale.commons.authz.context

import com.ideascale.commons.authz.resource.Resource

sealed interface ResourceContext {
    val workspaceId: String
    val type: Resource
    val id: String
}

data class WorkspaceContext(
    override val workspaceId: String
) : ResourceContext {
    override val type: Resource = Resource.WORKSPACE
    override val id: String = workspaceId
}

data class CommunityContext(
    override val workspaceId: String,
    val communityId: String
) : ResourceContext {
    override val type: Resource = Resource.COMMUNITY
    override val id: String = communityId
}

data class CampaignContext(
    override val workspaceId: String,
    val communityId: String,
    val campaignId: String
) : ResourceContext {
    override val type: Resource = Resource.CAMPAIGN
    override val id: String = campaignId
}

data class GroupContext(
    override val workspaceId: String,
    val groupId: String
) : ResourceContext {
    override val type: Resource = Resource.GROUP
    override val id: String = groupId
}

data class IdeaContext(
    override val workspaceId: String,
    val communityId: String,
    val campaignId: String,
    val ideaId: String
) : ResourceContext {
    override val type: Resource = Resource.IDEA
    override val id: String = ideaId
}

data class MemberContext(
    override val workspaceId: String,
    val memberId: String
) : ResourceContext {
    override val type: Resource = Resource.MEMBER
    override val id: String = memberId
}
