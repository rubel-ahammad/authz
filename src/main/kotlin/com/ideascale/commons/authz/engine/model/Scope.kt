package com.ideascale.commons.authz.engine.model

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.resource.Resource

/**
 * Principal scope - defines who the policy applies to.
 *
 * Following Cedar's membership pattern:
 * - Scope answers: "Could this policy apply to this principal?"
 * - Role-based scopes check if principal has that role for ANY resource
 * - Conditions (in the policy) narrow down to specific resources
 *
 * Example:
 * ```kotlin
 * permit(
 *     principal = IsCampaignModerator,  // Scope: user is moderator of some campaign
 *     action = UPDATE,
 *     resource = IDEA
 * ).when {
 *     // Condition: user is moderator of THIS campaign
 *     principal.isCampaignModerator(idea.campaign.id)
 * }
 * ```
 */
sealed interface PrincipalScope {
    /** Matches any principal (authenticated or anonymous) */
    data object Any : PrincipalScope

    /** Matches only authenticated principals */
    data object Authenticated : PrincipalScope

    /** Matches only anonymous principals */
    data object Anonymous : PrincipalScope

    // === WORKSPACE ROLES ===

    /** Principal is a workspace admin */
    data object IsWorkspaceAdmin : PrincipalScope

    /** Principal is a workspace member (includes admin) */
    data object IsWorkspaceMember : PrincipalScope

    // === ADMIN ROLES ===

    /** Principal is admin of at least one community */
    data object IsCommunityAdmin : PrincipalScope

    /** Principal is admin of at least one campaign */
    data object IsCampaignAdmin : PrincipalScope

    // === MODERATOR ROLES ===

    /** Principal is moderator of at least one community */
    data object IsCommunityModerator : PrincipalScope

    /** Principal is moderator of at least one campaign */
    data object IsCampaignModerator : PrincipalScope

    /** Principal is moderator of at least one group */
    data object IsGroupModerator : PrincipalScope

    /** Principal is moderator of at least one custom field */
    data object IsCustomFieldModerator : PrincipalScope

    // === COMPOSITE SCOPES ===

    /** All scopes must match (AND) */
    data class All(val scopes: List<PrincipalScope>) : PrincipalScope

    /** Any scope must match (OR) */
    data class OneOf(val scopes: List<PrincipalScope>) : PrincipalScope
}

/**
 * Action scope - defines which CRUD actions the policy applies to.
 */
sealed interface ActionScope {
    /** Matches any action */
    data object Any : ActionScope

    /** Matches exact action */
    data class Exact(val action: Action) : ActionScope

    /** Matches any of the specified actions */
    data class OneOf(val actions: Set<Action>) : ActionScope
}

/**
 * Resource scope - defines which resources the policy applies to.
 */
sealed interface ResourceScope {
    /** Matches any resource */
    data object Any : ResourceScope

    /** Resource must be of specific type */
    data class OfType(val type: Resource) : ResourceScope

    /** Resource must be of any of specified types */
    data class OfTypes(val types: Set<Resource>) : ResourceScope
}

/**
 * Complete policy scope combining principal, action, and resource.
 */
data class PolicyScope(
    val principal: PrincipalScope = PrincipalScope.Any,
    val action: ActionScope = ActionScope.Any,
    val resource: ResourceScope = ResourceScope.Any
)
