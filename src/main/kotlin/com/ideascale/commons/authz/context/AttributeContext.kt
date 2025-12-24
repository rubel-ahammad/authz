package com.ideascale.commons.authz.context

import com.ideascale.commons.authz.Channel

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
    val isPublic: Boolean = false,
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
    val channel: Channel,
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
