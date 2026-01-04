package com.ideascale.commons.authz.engine.dsl

import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.engine.model.*
import com.ideascale.commons.authz.Channel
import com.ideascale.commons.authz.PrincipalType

/**
 * DSL builder for policy conditions.
 * Multiple conditions are implicitly ANDed.
 *
 * Usage:
 * ```kotlin
 * `when` {
 *     role { isWorkspaceAdmin() }
 *     relationship { isIdeaOwner() }
 *     attribute { subscriptionState(SubscriptionState.ACTIVE) }
 *     environment { channelIs(Channel.ADMIN_UI) }
 *     anyOf(
 *         { attribute { workspacePublic() } },
 *         { role { isWorkspaceAdmin() } }
 *     )
 * }
 * ```
 */
@CedarDslMarker
class ConditionBuilder {
    private val conditions = mutableListOf<PolicyCondition>()

    /**
     * Add a role-based condition (Membership pattern).
     * Checks if principal has a specific role for the resource being accessed.
     */
    fun role(init: RoleConditionBuilder.() -> Unit) {
        conditions.add(RoleConditionBuilder().apply(init).build())
    }

    /**
     * Add a relationship-based condition (Relationship pattern).
     * Checks principal-resource relationships like ownership.
     */
    fun relationship(init: RelationshipConditionBuilder.() -> Unit) {
        conditions.add(RelationshipConditionBuilder().apply(init).build())
    }

    /**
     * Add an attribute-based condition (ABAC).
     * Checks resource or principal attributes.
     */
    fun attribute(init: AttributeConditionBuilder.() -> Unit) {
        conditions.add(AttributeConditionBuilder().apply(init).build())
    }

    /**
     * Add a resource-context-based condition.
     * Checks resource context validity (tenant mismatch, etc.).
     */
    fun resource(init: ResourceConditionBuilder.() -> Unit) {
        conditions.add(ResourceConditionBuilder().apply(init).build())
    }

    /**
     * Add an environment-based condition.
     * Checks request metadata (channel, user agent).
     */
    fun environment(init: EnvironmentConditionBuilder.() -> Unit) {
        conditions.add(EnvironmentConditionBuilder().apply(init).build())
    }

    /**
     * Add a custom condition with lambda.
     */
    fun custom(id: String, predicate: (ConditionContext) -> Boolean) {
        conditions.add(CustomCondition(id, predicate))
    }

    /**
     * Negate a condition.
     */
    fun not(init: ConditionBuilder.() -> Unit) {
        val innerConditions = ConditionBuilder().apply(init).build()
        if (innerConditions.isNotEmpty()) {
            conditions.add(NotCondition(AndCondition(innerConditions)))
        }
    }

    /**
     * OR combinator for grouped conditions (each group is ANDed internally).
     */
    fun anyOf(vararg builders: ConditionBuilder.() -> Unit) {
        val groups = builders.map { ConditionBuilder().apply(it).build() }
        val orConditions = groups.mapNotNull { group ->
            when (group.size) {
                0 -> null
                1 -> group.first()
                else -> AndCondition(group)
            }
        }
        if (orConditions.isNotEmpty()) {
            conditions.add(OrCondition(orConditions))
        }
    }

    fun build(): List<PolicyCondition> = conditions.toList()
}

/**
 * Builder for role-based conditions (Membership pattern).
 *
 * These conditions check if the principal has a specific role
 * for the SPECIFIC resource being accessed (not just any resource).
 */
@CedarDslMarker
class RoleConditionBuilder {
    private var condition: PolicyCondition? = null

    // === Workspace Roles ===

    /** Check if principal is a workspace admin */
    fun isWorkspaceAdmin() {
        condition = IsWorkspaceAdminCondition
    }

    // === Admin Roles (for specific resource) ===

    /** Check if principal is admin of the community in resource context */
    fun isCommunityAdmin() {
        condition = IsCommunityAdminCondition
    }

    /** Check if principal is admin of the campaign in resource context */
    fun isCampaignAdmin() {
        condition = IsCampaignAdminCondition
    }

    // === Moderator Roles (for specific resource) ===

    /** Check if principal is moderator of the community in resource context */
    fun isCommunityModerator() {
        condition = IsCommunityModeratorCondition
    }

    /** Check if principal is moderator of the campaign in resource context */
    fun isCampaignModerator() {
        condition = IsCampaignModeratorCondition
    }

    /** Check if principal is moderator of the group in resource context */
    fun isGroupModerator() {
        condition = IsGroupModeratorCondition
    }

    /** Check if principal is moderator of the custom field in resource context */
    fun isCustomFieldModerator() {
        condition = IsCustomFieldModeratorCondition
    }

    fun build(): PolicyCondition = condition
        ?: throw IllegalStateException("No role condition specified")
}

/**
 * Builder for relationship-based conditions (Relationship pattern).
 *
 * These conditions check direct relationships between principal and resource,
 * such as ownership or group membership.
 */
@CedarDslMarker
class RelationshipConditionBuilder {
    private var condition: PolicyCondition? = null

    /** Check if principal is owner of the idea */
    fun isIdeaOwner() {
        condition = IsIdeaOwnerCondition
    }

    /** Check if principal is a contributor to the idea */
    fun isIdeaContributor() {
        condition = IsIdeaContributorCondition
    }

    /** Check if principal is a viewer of the idea */
    fun isIdeaViewer() {
        condition = IsIdeaViewerCondition
    }

    /** Check if principal has any relationship to the idea */
    fun hasIdeaRelationship() {
        condition = HasIdeaRelationshipCondition
    }

    /** Check if principal is a member of the group */
    fun isGroupMember() {
        condition = IsGroupMemberCondition
    }

    fun build(): PolicyCondition = condition
        ?: throw IllegalStateException("No relationship condition specified")
}

/**
 * Builder for resource-context conditions.
 */
@CedarDslMarker
class ResourceConditionBuilder {
    private var condition: PolicyCondition? = null

    /** Deny if resource context is missing or tenant does not match */
    fun tenantMismatch() {
        condition = TenantMismatchCondition
    }

    /** Deny if resource context does not match the requested resource */
    fun resourceContextMismatch() {
        condition = ResourceContextMismatchCondition
    }

    fun build(): PolicyCondition = condition
        ?: throw IllegalStateException("No resource condition specified")
}

/**
 * Builder for environment-based conditions.
 */
@CedarDslMarker
class EnvironmentConditionBuilder {
    private var condition: PolicyCondition? = null

    /** Check if request channel is one of the specified channels */
    fun channelIs(vararg channels: Channel) {
        condition = ChannelCondition(channels.toSet())
    }

    /** Check if request channel is NOT one of the specified channels */
    fun channelIsNot(vararg channels: Channel) {
        condition = ChannelCondition(channels.toSet(), negate = true)
    }

    /** Check if user agent contains any of the provided tokens */
    fun userAgentContains(vararg tokens: String) {
        condition = UserAgentContainsCondition(tokens.toSet())
    }

    /** Check if user agent does NOT contain any of the provided tokens */
    fun userAgentNotContains(vararg tokens: String) {
        condition = UserAgentContainsCondition(tokens.toSet(), negate = true)
    }

    fun build(): PolicyCondition = condition
        ?: throw IllegalStateException("No environment condition specified")
}

/**
 * Builder for attribute-based conditions (ABAC).
 */
@CedarDslMarker
class AttributeConditionBuilder {
    private var condition: PolicyCondition? = null

    // ========== Principal Identity ==========

    /** Check if principal type is one of the specified types */
    fun principalType(vararg types: PrincipalType) {
        condition = PrincipalTypeCondition(types.toSet())
    }

    /** Check if principal type is NOT one of the specified types */
    fun principalTypeNot(vararg types: PrincipalType) {
        condition = PrincipalTypeCondition(types.toSet(), negate = true)
    }

    /** Check if principal is impersonating */
    fun impersonating() {
        condition = ImpersonatingCondition(true)
    }

    /** Check if principal is NOT impersonating */
    fun notImpersonating() {
        condition = ImpersonatingCondition(false)
    }

    // ========== Idea State ==========

    /** Check if idea is in specified state(s) */
    fun ideaState(vararg states: IdeaState) {
        condition = IdeaStateCondition(states.toSet())
    }

    /** Check if idea is NOT in specified state(s) */
    fun ideaStateNot(vararg states: IdeaState) {
        condition = IdeaStateCondition(states.toSet(), negate = true)
    }

    // ========== Campaign State ==========

    /** Check if campaign is in specified state(s) */
    fun campaignState(vararg states: CampaignState) {
        condition = CampaignStateCondition(states.toSet())
    }

    /** Check if campaign is NOT in specified state(s) */
    fun campaignStateNot(vararg states: CampaignState) {
        condition = CampaignStateCondition(states.toSet(), negate = true)
    }

    // ========== Community Status ==========

    /** Check if community is in specified status(es) */
    fun communityStatus(vararg statuses: CommunityStatus) {
        condition = CommunityStatusCondition(statuses.toSet())
    }

    /** Check if community is NOT in specified status(es) */
    fun communityStatusNot(vararg statuses: CommunityStatus) {
        condition = CommunityStatusCondition(statuses.toSet(), negate = true)
    }

    /** Check if community is private */
    fun communityPrivate() {
        condition = CommunityPrivateCondition(true)
    }

    /** Check if community is public */
    fun communityPublic() {
        condition = CommunityPrivateCondition(false)
    }

    // ========== Member Status ==========

    /** Check if member is in specified status(es) */
    fun memberStatus(vararg statuses: MemberStatus) {
        condition = MemberStatusCondition(statuses.toSet())
    }

    /** Check if member is NOT in specified status(es) */
    fun memberStatusNot(vararg statuses: MemberStatus) {
        condition = MemberStatusCondition(statuses.toSet(), negate = true)
    }

    // ========== Email Domain ==========

    /** Check if principal email domain is allowed by workspace policy */
    fun emailDomainAllowed() {
        condition = EmailDomainAllowedCondition(true)
    }

    /** Check if principal email domain is NOT allowed by workspace policy */
    fun emailDomainNotAllowed() {
        condition = EmailDomainAllowedCondition(false)
    }

    // ========== Subscription State ==========

    /** Check if subscription is in specified state(s) */
    fun subscriptionState(vararg states: SubscriptionState) {
        condition = SubscriptionStateCondition(states.toSet())
    }

    /** Check if subscription is NOT in specified state(s) */
    fun subscriptionStateNot(vararg states: SubscriptionState) {
        condition = SubscriptionStateCondition(states.toSet(), negate = true)
    }

    // ========== Workspace Flags ==========

    /** Check if workspace is in read-only mode */
    fun workspaceReadOnly() {
        condition = WorkspaceReadOnlyCondition(true)
    }

    /** Check if workspace is NOT in read-only mode */
    fun workspaceNotReadOnly() {
        condition = WorkspaceReadOnlyCondition(false)
    }

    /** Check if workspace is public */
    fun workspacePublic() {
        condition = WorkspacePublicCondition(true)
    }

    /** Check if workspace is private */
    fun workspacePrivate() {
        condition = WorkspacePublicCondition(false)
    }

    // ========== IP Restriction ==========

    /** Check if request IP is in a fixed list (exact match) */
    fun requestIpIn(vararg ips: String) {
        condition = RequestIpInCondition(ips.toSet())
    }

    /** Check if request IP is NOT in a fixed list (exact match) */
    fun requestIpNotIn(vararg ips: String) {
        condition = RequestIpInCondition(ips.toSet(), negate = true)
    }

    /** Check if request is IP restricted (denied) */
    fun ipRestricted() {
        condition = IpRestrictedCondition(true)
    }

    /** Check if request is NOT IP restricted */
    fun ipNotRestricted() {
        condition = IpRestrictedCondition(false)
    }

    fun build(): PolicyCondition = condition
        ?: throw IllegalStateException("No attribute condition specified")
}
