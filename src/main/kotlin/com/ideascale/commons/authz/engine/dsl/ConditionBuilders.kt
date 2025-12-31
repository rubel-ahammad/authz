package com.ideascale.commons.authz.engine.dsl

import com.ideascale.commons.authz.engine.model.*
import com.ideascale.commons.authz.context.*

/**
 * DSL builder for policy conditions.
 * Multiple conditions are implicitly ANDed.
 *
 * Usage:
 * ```kotlin
 * `when` {
 *     role { hasRole(Role.WORKSPACE_ADMIN) }
 *     relationship { isOwner() }
 * }
 * ```
 */
@CedarDslMarker
class ConditionBuilder {
    private val conditions = mutableListOf<PolicyCondition>()

    /**
     * Add a role-based condition (Membership permission).
     */
    fun role(init: RoleConditionBuilder.() -> Unit) {
        conditions.add(RoleConditionBuilder().apply(init).build())
    }

    /**
     * Add a relationship-based condition (Relationship permission).
     */
    fun relationship(init: RelationshipConditionBuilder.() -> Unit) {
        conditions.add(RelationshipConditionBuilder().apply(init).build())
    }

    /**
     * Add an attribute-based condition.
     */
    fun attribute(init: AttributeConditionBuilder.() -> Unit) {
        conditions.add(AttributeConditionBuilder().apply(init).build())
    }

    /**
     * Add a resource-context-based condition.
     */
    fun resource(init: ResourceConditionBuilder.() -> Unit) {
        conditions.add(ResourceConditionBuilder().apply(init).build())
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

    fun build(): List<PolicyCondition> = conditions.toList()
}

/**
 * Builder for role-based conditions (Membership permissions).
 */
@CedarDslMarker
class RoleConditionBuilder {
    private var condition: PolicyCondition? = null

    /** Check if principal has specific role at any level */
    fun hasRole(role: Role) {
        condition = HasRoleCondition(role)
    }

    /** Check if principal has specific role at specific level */
    fun hasRole(role: Role, at: RoleLevel) {
        condition = HasRoleCondition(role, at)
    }

    /** Check if principal has any of the specified roles (2 roles) */
    fun hasAnyRole(first: Role, second: Role) {
        condition = HasAnyRoleCondition(setOf(first, second))
    }

    /** Check if principal has any of the specified roles (3 roles) */
    fun hasAnyRole(first: Role, second: Role, third: Role) {
        condition = HasAnyRoleCondition(setOf(first, second, third))
    }

    /** Check if principal has any of the specified roles */
    fun hasAnyRole(roles: Set<Role>) {
        condition = HasAnyRoleCondition(roles)
    }

    /** Check if principal has any of the specified roles at specific level */
    fun hasAnyRole(roles: Set<Role>, at: RoleLevel) {
        condition = HasAnyRoleCondition(roles, at)
    }

    fun build(): PolicyCondition = condition
        ?: throw IllegalStateException("No role condition specified")
}

/**
 * Builder for relationship-based conditions (Relationship permissions).
 */
@CedarDslMarker
class RelationshipConditionBuilder {
    private var condition: PolicyCondition? = null

    /** Check if principal is owner of the resource */
    fun isOwner() {
        condition = IsOwnerCondition()
    }

    /** Check if principal is owner of an idea */
    fun isIdeaOwner() {
        condition = IsOwnerCondition(OwnershipType.IDEA)
    }

    /** Check if principal has access via specific groups */
    fun inGroup(vararg groupIds: String) {
        condition = InGroupCondition(groupIds.toSet())
    }

    /** Check if principal has access via any group */
    fun inAnyGroup() {
        condition = InGroupCondition(null)
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
 * Builder for attribute-based conditions.
 */
@CedarDslMarker
class AttributeConditionBuilder {
    private var condition: PolicyCondition? = null

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

    // ========== Member Status ==========

    /** Check if member is in specified status(es) */
    fun memberStatus(vararg statuses: MemberStatus) {
        condition = MemberStatusCondition(statuses.toSet())
    }

    /** Check if member is NOT in specified status(es) */
    fun memberStatusNot(vararg statuses: MemberStatus) {
        condition = MemberStatusCondition(statuses.toSet(), negate = true)
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
