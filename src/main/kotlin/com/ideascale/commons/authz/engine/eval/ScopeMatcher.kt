package com.ideascale.commons.authz.engine.eval

import com.ideascale.commons.authz.Subject
import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.action.ActionMatcher
import com.ideascale.commons.authz.engine.model.*
import com.ideascale.commons.authz.context.RoleContext
import com.ideascale.commons.authz.resource.ResourceRef

/**
 * Matches authorization requests against policy scopes.
 */
object ScopeMatcher {

    /**
     * Check if a request matches the complete policy scope.
     */
    fun matches(
        subject: Subject,
        action: Action,
        resource: ResourceRef,
        roleContext: RoleContext?,
        scope: PolicyScope
    ): Boolean =
        matchesPrincipal(subject, roleContext, scope.principal) &&
        matchesAction(action, scope.action) &&
        matchesResource(resource, scope.resource)

    /**
     * Check if subject matches principal scope.
     */
    fun matchesPrincipal(
        subject: Subject,
        roleContext: RoleContext?,
        scope: PrincipalScope
    ): Boolean = when (scope) {
        is PrincipalScope.Any -> true

        is PrincipalScope.Authenticated -> !subject.isAnonymous

        is PrincipalScope.Anonymous -> subject.isAnonymous

        is PrincipalScope.HasRole -> {
            val rc = roleContext ?: return false
            scope.roleId in rc.workspaceRoles ||
            scope.roleId in rc.communityRoles ||
            scope.roleId in rc.campaignRoles ||
            scope.roleId in rc.groupRoles
        }

        is PrincipalScope.HasRoleAt -> {
            val rc = roleContext ?: return false
            when (scope.level) {
                RoleLevel.WORKSPACE -> scope.roleId in rc.workspaceRoles
                RoleLevel.COMMUNITY -> scope.roleId in rc.communityRoles
                RoleLevel.CAMPAIGN -> scope.roleId in rc.campaignRoles
                RoleLevel.GROUP -> scope.roleId in rc.groupRoles
            }
        }

        is PrincipalScope.HasAnyRole -> {
            val rc = roleContext ?: return false
            scope.roleIds.any { roleId ->
                roleId in rc.workspaceRoles ||
                roleId in rc.communityRoles ||
                roleId in rc.campaignRoles ||
                roleId in rc.groupRoles
            }
        }

        is PrincipalScope.All -> scope.scopes.all {
            matchesPrincipal(subject, roleContext, it)
        }

        is PrincipalScope.OneOf -> scope.scopes.any {
            matchesPrincipal(subject, roleContext, it)
        }
    }

    /**
     * Check if action matches action scope.
     */
    fun matchesAction(action: Action, scope: ActionScope): Boolean =
        ActionMatcher.matches(action, scope)

    /**
     * Check if resource matches resource scope.
     */
    fun matchesResource(resource: ResourceRef, scope: ResourceScope): Boolean =
        when (scope) {
            is ResourceScope.Any -> true
            is ResourceScope.OfType -> resource.type == scope.type
            is ResourceScope.OfTypes -> resource.type in scope.types
            is ResourceScope.Exact -> resource.type == scope.type && resource.id == scope.id
        }
}
