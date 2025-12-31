package com.ideascale.commons.authz.engine.model

import com.ideascale.commons.authz.Principal
import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.resource.Resource

/**
 * Context available for condition evaluation.
 */
data class ConditionContext(
    val principal: Principal,
    val resource: Resource,
    val roleContext: RoleContext?,
    val resourceContext: ResourceContext?,
    val relationshipContext: RelationshipContext?,
    val attributeContext: AttributeContext?
)

/**
 * Policy condition that must evaluate to true for the policy to apply.
 * Multiple conditions in a policy are implicitly ANDed.
 */
sealed interface PolicyCondition {
    fun evaluate(ctx: ConditionContext): Boolean
}

// ============================================================================
// Logical Conditions
// ============================================================================

/**
 * All conditions must be true (AND).
 */
data class AndCondition(val conditions: List<PolicyCondition>) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean =
        conditions.all { it.evaluate(ctx) }
}

/**
 * Negates the condition (NOT).
 */
data class NotCondition(val condition: PolicyCondition) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean =
        !condition.evaluate(ctx)
}

// ============================================================================
// Role Conditions (Membership Permissions)
// ============================================================================

/**
 * Checks if principal has a specific role.
 */
data class HasRoleCondition(
    val role: Role,
    val level: RoleLevel? = null
) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val roleCtx = ctx.roleContext ?: return false
        return when (level) {
            null -> role in roleCtx.workspaceRoles ||
                    role in roleCtx.communityRoles ||
                    role in roleCtx.campaignRoles ||
                    role in roleCtx.groupRoles
            RoleLevel.WORKSPACE -> role in roleCtx.workspaceRoles
            RoleLevel.COMMUNITY -> role in roleCtx.communityRoles
            RoleLevel.CAMPAIGN -> role in roleCtx.campaignRoles
            RoleLevel.GROUP -> role in roleCtx.groupRoles
        }
    }
}

/**
 * Checks if principal has any of the specified roles.
 */
data class HasAnyRoleCondition(
    val roles: Set<Role>,
    val level: RoleLevel? = null
) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val roleCtx = ctx.roleContext ?: return false
        return roles.any { role ->
            when (level) {
                null -> role in roleCtx.workspaceRoles ||
                        role in roleCtx.communityRoles ||
                        role in roleCtx.campaignRoles ||
                        role in roleCtx.groupRoles
                RoleLevel.WORKSPACE -> role in roleCtx.workspaceRoles
                RoleLevel.COMMUNITY -> role in roleCtx.communityRoles
                RoleLevel.CAMPAIGN -> role in roleCtx.campaignRoles
                RoleLevel.GROUP -> role in roleCtx.groupRoles
            }
        }
    }
}

// ============================================================================
// Relationship Conditions (Relationship Permissions)
// ============================================================================

/**
 * Checks if principal is the owner of the resource.
 */
data class IsOwnerCondition(val of: OwnershipType = OwnershipType.IDEA) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val relCtx = ctx.relationshipContext ?: return false
        return when (of) {
            OwnershipType.IDEA -> relCtx.isIdeaOwner
        }
    }
}

enum class OwnershipType { IDEA }

/**
 * Checks if principal has access via group membership.
 */
data class InGroupCondition(val groupIds: Set<String>? = null) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val relCtx = ctx.relationshipContext ?: return false
        return if (groupIds == null) {
            relCtx.viaGroupIds.isNotEmpty()
        } else {
            relCtx.viaGroupIds.any { it in groupIds }
        }
    }
}

// ============================================================================
// Resource Context Conditions
// ============================================================================

/**
 * Checks if the request crosses tenant boundaries or lacks resource context.
 */
data object TenantMismatchCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val resourceWorkspaceId = ctx.resourceContext?.workspaceId ?: return true
        return resourceWorkspaceId != ctx.principal.workspaceId
    }
}

/**
 * Checks if resource context doesn't match the requested resource (or is missing).
 */
data object ResourceContextMismatchCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val resourceCtx = ctx.resourceContext ?: return true
        return resourceCtx.type != ctx.resource
    }
}

// ============================================================================
// Attribute Conditions
// ============================================================================

/**
 * Checks idea state.
 */
data class IdeaStateCondition(
    val states: Set<IdeaState>,
    val negate: Boolean = false
) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val ideaState = ctx.attributeContext?.idea?.state ?: return false
        val matches = ideaState in states
        return if (negate) !matches else matches
    }
}

/**
 * Checks campaign state.
 */
data class CampaignStateCondition(
    val states: Set<CampaignState>,
    val negate: Boolean = false
) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val campaignState = ctx.attributeContext?.campaign?.state ?: return false
        val matches = campaignState in states
        return if (negate) !matches else matches
    }
}

/**
 * Checks community status.
 */
data class CommunityStatusCondition(
    val statuses: Set<CommunityStatus>,
    val negate: Boolean = false
) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val status = ctx.attributeContext?.community?.status ?: return false
        val matches = status in statuses
        return if (negate) !matches else matches
    }
}

/**
 * Checks member status.
 */
data class MemberStatusCondition(
    val statuses: Set<MemberStatus>,
    val negate: Boolean = false
) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val status = ctx.attributeContext?.member?.status ?: return false
        val matches = status in statuses
        return if (negate) !matches else matches
    }
}

/**
 * Checks subscription state.
 */
data class SubscriptionStateCondition(
    val states: Set<SubscriptionState>,
    val negate: Boolean = false
) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val state = ctx.attributeContext?.workspace?.subscription?.state ?: return false
        val matches = state in states
        return if (negate) !matches else matches
    }
}

/**
 * Checks if workspace is in read-only mode.
 */
data class WorkspaceReadOnlyCondition(val isReadOnly: Boolean = true) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val flags = ctx.attributeContext?.workspace?.flags ?: return false
        return flags.isReadOnlyMode == isReadOnly
    }
}

/**
 * Checks if workspace is public.
 */
data class WorkspacePublicCondition(val isPublic: Boolean = true) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val flags = ctx.attributeContext?.workspace?.flags ?: return false
        return flags.isPublic == isPublic
    }
}

/**
 * Checks request IP against a fixed allow/deny list (exact match).
 */
data class RequestIpInCondition(
    val ips: Set<String>,
    val negate: Boolean = false
) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val ip = ctx.attributeContext?.request?.ip ?: return false
        val matches = ip in ips
        return if (negate) !matches else matches
    }
}

/**
 * Checks IP restriction result.
 */
data class IpRestrictedCondition(val isDenied: Boolean = true) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val result = ctx.attributeContext?.workspace?.network?.ipRestriction ?: return false
        val denied = result is IpRestrictionResult.Denied
        return denied == isDenied
    }
}

// ============================================================================
// Custom Condition
// ============================================================================

/**
 * Custom condition with lambda for flexibility.
 */
data class CustomCondition(
    val id: String,
    val predicate: (ConditionContext) -> Boolean
) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean = predicate(ctx)
}
