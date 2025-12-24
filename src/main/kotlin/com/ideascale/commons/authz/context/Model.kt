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

@JvmInline
value class RoleId(val value: String) {
    init {
        require(value.isNotBlank()) { "RoleId cannot be blank" }
    }

    override fun toString(): String = value
}

object RoleIds {
    val WORKSPACE_ADMIN = RoleId("WORKSPACE_ADMIN")
    val WORKSPACE_MEMBER = RoleId("WORKSPACE_MEMBER")
    val CAMPAIGN_MODERATOR = RoleId("CAMPAIGN_MODERATOR")
    val ANONYMOUS = RoleId("ANONYMOUS")
    val ADMIN = RoleId("ADMIN")
}

data class RelationshipContext(
    val isIdeaOwner: Boolean = false,
    val viaGroupIds: Set<String> = emptySet()
)

data class AttributeContext(
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
    val channel: com.ideascale.commons.authz.core.Channel,
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

data class RoleContext(
    val workspaceRoles: Set<RoleId> = emptySet(),
    val communityRoles: Set<RoleId> = emptySet(),
    val campaignRoles: Set<RoleId> = emptySet(),
    val groupRoles: Set<RoleId> = emptySet()
)
