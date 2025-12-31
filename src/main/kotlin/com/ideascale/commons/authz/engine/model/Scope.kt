package com.ideascale.commons.authz.engine.model

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.context.RoleId
import com.ideascale.commons.authz.resource.Resource

/**
 * Role level for role-based scope matching.
 */
enum class RoleLevel {
    WORKSPACE,
    COMMUNITY,
    CAMPAIGN,
    GROUP
}

/**
 * Principal scope - defines who the policy applies to.
 */
sealed interface PrincipalScope {
    /** Matches any principal (authenticated or anonymous) */
    data object Any : PrincipalScope

    /** Matches only authenticated principals */
    data object Authenticated : PrincipalScope

    /** Matches only anonymous principals */
    data object Anonymous : PrincipalScope

    /** Principal must have specific role at any level */
    data class HasRole(val roleId: RoleId) : PrincipalScope

    /** Principal must have role at specific level */
    data class HasRoleAt(val roleId: RoleId, val level: RoleLevel) : PrincipalScope

    /** Principal must have any of the specified roles */
    data class HasAnyRole(val roleIds: Set<RoleId>) : PrincipalScope

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
