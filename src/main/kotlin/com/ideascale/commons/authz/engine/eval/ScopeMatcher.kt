package com.ideascale.commons.authz.engine.eval

import com.ideascale.commons.authz.Principal
import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.context.PrincipalContext
import com.ideascale.commons.authz.context.WorkspaceRole
import com.ideascale.commons.authz.engine.model.*
import com.ideascale.commons.authz.resource.Resource

/**
 * Matches authorization requests against policy scopes.
 *
 * Scope matching determines if a policy COULD apply to a request.
 * For role-based scopes, it checks if the principal has that role for ANY resource.
 * The policy's conditions then narrow down to the specific resource.
 */
object ScopeMatcher {

    /**
     * Check if a request matches the complete policy scope.
     */
    fun matches(
        principal: Principal,
        action: Action,
        resource: Resource,
        principalContext: PrincipalContext?,
        scope: PolicyScope
    ): Boolean =
        matchesPrincipal(principal, principalContext, scope.principal) &&
        matchesAction(action, scope.action) &&
        matchesResource(resource, scope.resource)

    /**
     * Check if principal matches principal scope.
     *
     * For role-based scopes, checks if principal has that role for ANY resource.
     * Example: IsCampaignModerator matches if user moderates at least one campaign.
     */
    fun matchesPrincipal(
        principal: Principal,
        principalContext: PrincipalContext?,
        scope: PrincipalScope
    ): Boolean = when (scope) {
        is PrincipalScope.Any -> true

        is PrincipalScope.Authenticated -> !principal.isAnonymous

        is PrincipalScope.Anonymous -> principal.isAnonymous

        // Workspace roles
        is PrincipalScope.IsWorkspaceAdmin -> {
            val ctx = principalContext ?: return false
            ctx.workspaceRole == WorkspaceRole.ADMIN
        }

        is PrincipalScope.IsWorkspaceMember -> {
            val ctx = principalContext ?: return false
            ctx.workspaceRole == WorkspaceRole.ADMIN || ctx.workspaceRole == WorkspaceRole.MEMBER
        }

        // Admin roles - check if admin of at least one resource
        is PrincipalScope.IsCommunityAdmin -> {
            val ctx = principalContext ?: return false
            ctx.communityAdmin.isNotEmpty()
        }

        is PrincipalScope.IsCampaignAdmin -> {
            val ctx = principalContext ?: return false
            ctx.campaignAdmin.isNotEmpty()
        }

        // Moderator roles - check if moderator of at least one resource
        is PrincipalScope.IsCommunityModerator -> {
            val ctx = principalContext ?: return false
            ctx.communityModerator.isNotEmpty()
        }

        is PrincipalScope.IsCampaignModerator -> {
            val ctx = principalContext ?: return false
            ctx.campaignModerator.isNotEmpty()
        }

        is PrincipalScope.IsGroupModerator -> {
            val ctx = principalContext ?: return false
            ctx.groupModerator.isNotEmpty()
        }

        is PrincipalScope.IsCustomFieldModerator -> {
            val ctx = principalContext ?: return false
            ctx.customFieldModerator.isNotEmpty()
        }

        // Composite scopes
        is PrincipalScope.All -> scope.scopes.all {
            matchesPrincipal(principal, principalContext, it)
        }

        is PrincipalScope.OneOf -> scope.scopes.any {
            matchesPrincipal(principal, principalContext, it)
        }
    }

    /**
     * Check if action matches action scope.
     */
    fun matchesAction(action: Action, scope: ActionScope): Boolean =
        when (scope) {
            is ActionScope.Any -> true
            is ActionScope.Exact -> action == scope.action
            is ActionScope.OneOf -> scope.actions.any { it == action }
        }

    /**
     * Check if resource matches resource scope.
     */
    fun matchesResource(resource: Resource, scope: ResourceScope): Boolean =
        when (scope) {
            is ResourceScope.Any -> true
            is ResourceScope.OfType -> resource == scope.type
            is ResourceScope.OfTypes -> resource in scope.types
        }
}
