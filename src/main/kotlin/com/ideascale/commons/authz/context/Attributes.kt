package com.ideascale.commons.authz.context

/**
 * Workspace-level attributes (always required in ResourceContext).
 * Represents tenant-level constraints that apply to all resources.
 */
data class WorkspaceAttributes(
    val id: Long,
    val subscriptionState: SubscriptionState = SubscriptionState.ACTIVE,
    val isPublic: Boolean = false,
    val isReadOnly: Boolean = false,
    val ipRestrictions: IpRestrictions? = null,
    val emailDomainPolicy: EmailDomainPolicy? = null
)

/**
 * Community attributes for resources within a community.
 */
data class CommunityAttributes(
    val id: Long,
    val status: CommunityStatus = CommunityStatus.ACTIVE,
    val isPrivate: Boolean = false
)

/**
 * Campaign attributes for resources within a campaign.
 */
data class CampaignAttributes(
    val id: Long,
    val state: CampaignState = CampaignState.LAUNCHED
)

// === ENUMS ===

enum class SubscriptionState { ACTIVE, BLOCKED, SOFT_BLOCKED, READ_ONLY }
enum class CommunityStatus { ACTIVE, ARCHIVED }
enum class CampaignState { LAUNCHED, EXPIRED, READONLY }
enum class IdeaState { ACTIVE, LOCKED, ARCHIVED }
enum class MemberStatus { ACTIVE, BANNED, PENDING }
enum class WorkspaceRole { ADMIN, MEMBER }

// === SUPPORTING TYPES ===

/**
 * IP restriction configuration for a workspace.
 */
data class IpRestrictions(
    val allowedRanges: Set<String>,
    val isEnforced: Boolean = true
)

/**
 * Email domain policy for a workspace.
 */
data class EmailDomainPolicy(
    val allowedDomains: Set<String>? = null,
    val blockedDomains: Set<String> = emptySet()
) {
    fun isAllowed(domain: String): Boolean {
        if (blockedDomains.contains(domain)) return false
        return allowedDomains == null || allowedDomains.contains(domain)
    }
}
