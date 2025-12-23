package com.ideascale.authz.engine

sealed interface ResourceContextFacts {
    val workspaceId: String
}

data class WorkspaceContextFacts(
    override val workspaceId: String
) : ResourceContextFacts

data class CommunityContextFacts(
    override val workspaceId: String,
    val communityId: String
) : ResourceContextFacts

data class CampaignContextFacts(
    override val workspaceId: String,
    val communityId: String,
    val campaignId: String
) : ResourceContextFacts

data class IdeaContextFacts(
    override val workspaceId: String,
    val communityId: String,
    val campaignId: String,
    val ideaId: String
) : ResourceContextFacts

data class MemberContextFacts(
    override val workspaceId: String,
    val memberId: String
) : ResourceContextFacts

@JvmInline
value class RoleId(val value: String) {
    init {
        require(value.isNotBlank()) { "RoleId cannot be blank" }
    }

    override fun toString(): String = value
}

object RoleIds {
    val WORKSPACE_ADMIN = RoleId("WORKSPACE_ADMIN")
    val CAMPAIGN_MODERATOR = RoleId("CAMPAIGN_MODERATOR")
}

data class RelationshipFacts(
    val isWorkspaceMember: Boolean = false,
    val isIdeaOwner: Boolean = false,
    val viaGroupIds: Set<String> = emptySet()
)

data class AttributeFacts(
    val workspace: WorkspaceAttrs,
    val member: MemberAttrs,
    val request: RequestAttrs,
    val community: CommunityAttrs? = null,
    val campaign: CampaignAttrs? = null,
    val idea: IdeaAttrs? = null
)

data class WorkspaceAttrs(
    val subscription: SubscriptionAttrs,
    val network: NetworkAttrs,
    val emailDomain: EmailDomainAttrs,
    val flags: WorkspaceFlags = WorkspaceFlags()
)

data class SubscriptionAttrs(
    val state: SubscriptionState
)

data class NetworkAttrs(
    val ipRestriction: IpRestrictionResult
)

data class EmailDomainAttrs(
    val policy: EmailDomainPolicy = EmailDomainPolicy.NotApplicable
)

data class WorkspaceFlags(
    val isReadOnlyMode: Boolean = false
)

data class MemberAttrs(
    val status: MemberStatus
)

data class CommunityAttrs(
    val status: CommunityStatus? = null
)

data class CampaignAttrs(
    val state: CampaignState
)

data class IdeaAttrs(
    val state: IdeaState? = null
)

data class RequestAttrs(
    val ip: String?,
    val channel: com.ideascale.authz.core.Channel,
    val userAgent: String? = null
)

enum class MemberStatus { BANNED, PENDING, MEMBER }
enum class SubscriptionState { ACTIVE, BLOCKED, SOFT_BLOCKED }
enum class CampaignState { LAUNCHED, EXPIRED, READONLY }
enum class CommunityStatus { ACTIVE, ARCHIVED }
enum class IdeaState { ACTIVE, LOCKED, ARCHIVED }

sealed interface IpRestrictionResult {
    data object Allowed : IpRestrictionResult
    data class Denied(val reason: String) : IpRestrictionResult
}

sealed interface EmailDomainPolicy {
    data object NotApplicable : EmailDomainPolicy
    data class Allowed(val domain: String) : EmailDomainPolicy
    data class Blocked(val domain: String) : EmailDomainPolicy
}

data class RoleFacts(
    val workspaceRoles: Set<RoleId> = emptySet(),
    val communityRoles: Set<RoleId> = emptySet(),
    val campaignRoles: Set<RoleId> = emptySet(),
    val groupRoles: Set<RoleId> = emptySet()
)
