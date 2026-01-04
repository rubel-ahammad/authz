package com.ideascale.commons.authz.engine.model

import com.ideascale.commons.authz.Principal
import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.resource.Resource

/**
 * Context available for condition evaluation.
 *
 * Provides access to:
 * - Principal identity and context (roles + attributes)
 * - Action being requested
 * - Resource context (type-specific attributes and relationships)
 * - Environment context (request metadata)
 */
data class ConditionContext(
    val principal: Principal,
    val action: Action,
    val resource: Resource,
    val principalContext: PrincipalContext?,
    val resourceContext: ResourceContext?,
    val environmentContext: EnvironmentContext?
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
// Role Conditions (Membership Pattern)
// These check if principal has a role for the SPECIFIC resource being accessed
// ============================================================================

/**
 * Checks if principal is a workspace admin.
 */
data object IsWorkspaceAdminCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalCtx = ctx.principalContext ?: return false
        return principalCtx.isWorkspaceAdmin()
    }
}

/**
 * Checks if principal is admin of the community in the resource context.
 */
data object IsCommunityAdminCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalCtx = ctx.principalContext ?: return false
        val communityId = ctx.resourceContext?.let { extractCommunityId(it) } ?: return false
        return principalCtx.isCommunityAdmin(communityId)
    }
}

/**
 * Checks if principal is admin of the campaign in the resource context.
 */
data object IsCampaignAdminCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalCtx = ctx.principalContext ?: return false
        val campaignId = ctx.resourceContext?.let { extractCampaignId(it) } ?: return false
        return principalCtx.isCampaignAdmin(campaignId)
    }
}

/**
 * Checks if principal is moderator of the community in the resource context.
 */
data object IsCommunityModeratorCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalCtx = ctx.principalContext ?: return false
        val communityId = ctx.resourceContext?.let { extractCommunityId(it) } ?: return false
        return principalCtx.isCommunityModerator(communityId)
    }
}

/**
 * Checks if principal is moderator of the campaign in the resource context.
 */
data object IsCampaignModeratorCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalCtx = ctx.principalContext ?: return false
        val campaignId = ctx.resourceContext?.let { extractCampaignId(it) } ?: return false
        return principalCtx.isCampaignModerator(campaignId)
    }
}

/**
 * Checks if principal is moderator of the group in the resource context.
 */
data object IsGroupModeratorCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalCtx = ctx.principalContext ?: return false
        val resourceCtx = ctx.resourceContext
        val groupId = when (resourceCtx) {
            is GroupContext -> resourceCtx.id
            else -> return false
        }
        return principalCtx.isGroupModerator(groupId)
    }
}

/**
 * Checks if principal is moderator of the custom field in the resource context.
 */
data object IsCustomFieldModeratorCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalCtx = ctx.principalContext ?: return false
        val resourceCtx = ctx.resourceContext
        val fieldId = when (resourceCtx) {
            is CustomFieldContext -> resourceCtx.id
            else -> return false
        }
        return principalCtx.isCustomFieldModerator(fieldId)
    }
}

// ============================================================================
// Relationship Conditions (Relationship Pattern)
// ============================================================================

/**
 * Checks if principal is the owner of the idea.
 */
data object IsIdeaOwnerCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalId = ctx.principal.id ?: return false
        val resourceCtx = ctx.resourceContext
        return when (resourceCtx) {
            is IdeaContext -> resourceCtx.isOwner(principalId)
            else -> false
        }
    }
}

/**
 * Checks if principal is a contributor to the idea.
 */
data object IsIdeaContributorCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalId = ctx.principal.id ?: return false
        val resourceCtx = ctx.resourceContext
        return when (resourceCtx) {
            is IdeaContext -> resourceCtx.isContributor(principalId)
            else -> false
        }
    }
}

/**
 * Checks if principal is a viewer of the idea.
 */
data object IsIdeaViewerCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalId = ctx.principal.id ?: return false
        val resourceCtx = ctx.resourceContext
        return when (resourceCtx) {
            is IdeaContext -> resourceCtx.isViewer(principalId)
            else -> false
        }
    }
}

/**
 * Checks if principal has any relationship to the idea (owner, contributor, or viewer).
 */
data object HasIdeaRelationshipCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalId = ctx.principal.id ?: return false
        val resourceCtx = ctx.resourceContext
        return when (resourceCtx) {
            is IdeaContext -> resourceCtx.hasAnyRelationship(principalId)
            else -> false
        }
    }
}

/**
 * Checks if principal is a member of the group.
 */
data object IsGroupMemberCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val principalId = ctx.principal.id ?: return false
        val resourceCtx = ctx.resourceContext
        return when (resourceCtx) {
            is GroupContext -> resourceCtx.isMember(principalId)
            else -> false
        }
    }
}

// ============================================================================
// Resource Context Conditions
// ============================================================================

/**
 * Checks if the request crosses tenant boundaries.
 */
data object TenantMismatchCondition : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val resourceWorkspaceId = ctx.resourceContext?.workspace?.id ?: return true
        return resourceWorkspaceId != ctx.principal.workspaceId
    }
}

/**
 * Checks if resource context doesn't match the requested resource type.
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
        val resourceCtx = ctx.resourceContext
        val ideaState = when (resourceCtx) {
            is IdeaContext -> resourceCtx.state
            else -> return false
        }
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
        val resourceCtx = ctx.resourceContext
        val campaignState = when (resourceCtx) {
            is CampaignContext -> resourceCtx.state
            is IdeaContext -> resourceCtx.campaign.state
            else -> return false
        }
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
        val resourceCtx = ctx.resourceContext
        val status = when (resourceCtx) {
            is CommunityContext -> resourceCtx.status
            is CampaignContext -> resourceCtx.community.status
            is IdeaContext -> resourceCtx.community.status
            else -> return false
        }
        val matches = status in statuses
        return if (negate) !matches else matches
    }
}

/**
 * Checks principal's member status.
 */
data class MemberStatusCondition(
    val statuses: Set<MemberStatus>,
    val negate: Boolean = false
) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val status = ctx.principalContext?.status ?: return false
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
        val state = ctx.resourceContext?.workspace?.subscriptionState ?: return false
        val matches = state in states
        return if (negate) !matches else matches
    }
}

/**
 * Checks if workspace is in read-only mode.
 */
data class WorkspaceReadOnlyCondition(val isReadOnly: Boolean = true) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val workspaceReadOnly = ctx.resourceContext?.workspace?.isReadOnly ?: return false
        return workspaceReadOnly == isReadOnly
    }
}

/**
 * Checks if workspace is public.
 */
data class WorkspacePublicCondition(val isPublic: Boolean = true) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val workspacePublic = ctx.resourceContext?.workspace?.isPublic ?: return false
        return workspacePublic == isPublic
    }
}

/**
 * Checks if community is private.
 */
data class CommunityPrivateCondition(val isPrivate: Boolean = true) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val resourceCtx = ctx.resourceContext
        val communityPrivate = when (resourceCtx) {
            is CommunityContext -> resourceCtx.isPrivate
            is CampaignContext -> resourceCtx.community.isPrivate
            is IdeaContext -> resourceCtx.community.isPrivate
            else -> return false
        }
        return communityPrivate == isPrivate
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
        val ip = ctx.environmentContext?.ip ?: return false
        val matches = ip in ips
        return if (negate) !matches else matches
    }
}

/**
 * Checks if IP is restricted (denied by workspace IP restrictions).
 */
data class IpRestrictedCondition(val isDenied: Boolean = true) : PolicyCondition {
    override fun evaluate(ctx: ConditionContext): Boolean {
        val restrictions = ctx.resourceContext?.workspace?.ipRestrictions ?: return false
        val requestIp = ctx.environmentContext?.ip ?: return isDenied // No IP = denied if restrictions exist

        if (!restrictions.isEnforced) return !isDenied

        val isAllowed = restrictions.allowedRanges.any { range ->
            // Simple exact match for now - could be extended to CIDR
            requestIp == range || requestIp.startsWith(range.removeSuffix("*"))
        }
        return if (isDenied) !isAllowed else isAllowed
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

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Extract community ID from resource context, handling hierarchy.
 */
private fun extractCommunityId(resourceContext: ResourceContext): Long? = when (resourceContext) {
    is CommunityContext -> resourceContext.id
    is CampaignContext -> resourceContext.community.id
    is IdeaContext -> resourceContext.community.id
    is CustomFieldContext -> resourceContext.community?.id
    else -> null
}

/**
 * Extract campaign ID from resource context, handling hierarchy.
 */
private fun extractCampaignId(resourceContext: ResourceContext): Long? = when (resourceContext) {
    is CampaignContext -> resourceContext.id
    is IdeaContext -> resourceContext.campaign.id
    else -> null
}
