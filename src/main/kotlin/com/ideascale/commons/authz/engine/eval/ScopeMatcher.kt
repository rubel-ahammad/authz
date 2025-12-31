package com.ideascale.commons.authz.engine.eval

import com.ideascale.commons.authz.Principal
import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.context.RoleContext
import com.ideascale.commons.authz.engine.model.*
import com.ideascale.commons.authz.resource.Resource

/**
 * Matches authorization requests against policy scopes.
 */
object ScopeMatcher {

    /**
     * Check if a request matches the complete policy scope.
     */
    fun matches(
        principal: Principal,
        action: Action,
        resource: Resource,
        roleContext: RoleContext?,
        scope: PolicyScope
    ): Boolean =
        matchesPrincipal(principal, roleContext, scope.principal) &&
        matchesAction(action, scope.action) &&
        matchesResource(resource, scope.resource)

    /**
     * Check if principal matches principal scope.
     */
    fun matchesPrincipal(
        principal: Principal,
        roleContext: RoleContext?,
        scope: PrincipalScope
    ): Boolean = when (scope) {
        is PrincipalScope.Any -> true

        is PrincipalScope.Authenticated -> !principal.isAnonymous

        is PrincipalScope.Anonymous -> principal.isAnonymous

        is PrincipalScope.HasRole -> {
            val rc = roleContext ?: return false
            scope.role in rc.workspaceRoles ||
            scope.role in rc.communityRoles ||
            scope.role in rc.campaignRoles ||
            scope.role in rc.groupRoles
        }

        is PrincipalScope.HasRoleAt -> {
            val rc = roleContext ?: return false
            when (scope.level) {
                RoleLevel.WORKSPACE -> scope.role in rc.workspaceRoles
                RoleLevel.COMMUNITY -> scope.role in rc.communityRoles
                RoleLevel.CAMPAIGN -> scope.role in rc.campaignRoles
                RoleLevel.GROUP -> scope.role in rc.groupRoles
            }
        }

        is PrincipalScope.HasAnyRole -> {
            val rc = roleContext ?: return false
            scope.roles.any { role ->
                role in rc.workspaceRoles ||
                role in rc.communityRoles ||
                role in rc.campaignRoles ||
                role in rc.groupRoles
            }
        }

        is PrincipalScope.All -> scope.scopes.all {
            matchesPrincipal(principal, roleContext, it)
        }

        is PrincipalScope.OneOf -> scope.scopes.any {
            matchesPrincipal(principal, roleContext, it)
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
