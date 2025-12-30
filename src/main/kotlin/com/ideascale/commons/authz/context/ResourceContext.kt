package com.ideascale.commons.authz.context

import com.ideascale.commons.authz.resource.ResourceType

sealed interface ResourceContext {
    val workspaceId: String
    val type: ResourceType
    val id: String
}

data class WorkspaceContext(
    override val workspaceId: String
) : ResourceContext {
    override val type: ResourceType = ResourceType.WORKSPACE
    override val id: String = workspaceId
}

data class CommunityContext(
    override val workspaceId: String,
    val communityId: String
) : ResourceContext {
    override val type: ResourceType = ResourceType.COMMUNITY
    override val id: String = communityId
}

data class CampaignContext(
    override val workspaceId: String,
    val communityId: String,
    val campaignId: String
) : ResourceContext {
    override val type: ResourceType = ResourceType.CAMPAIGN
    override val id: String = campaignId
}

data class GroupContext(
    override val workspaceId: String,
    val groupId: String
) : ResourceContext {
    override val type: ResourceType = ResourceType.GROUP
    override val id: String = groupId
}

data class IdeaContext(
    override val workspaceId: String,
    val communityId: String,
    val campaignId: String,
    val ideaId: String
) : ResourceContext {
    override val type: ResourceType = ResourceType.IDEA
    override val id: String = ideaId
}

data class MemberContext(
    override val workspaceId: String,
    val memberId: String
) : ResourceContext {
    override val type: ResourceType = ResourceType.MEMBER
    override val id: String = memberId
}
