package com.ideascale.commons.authz.engine.dsl

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.engine.model.*
import com.ideascale.commons.authz.resource.Resource

/**
 * DSL builder for PrincipalScope.
 *
 * Usage:
 * ```kotlin
 * principal = {
 *     isWorkspaceAdmin()
 * }
 * ```
 */
@CedarDslMarker
class PrincipalScopeBuilder {
    private var scope: PrincipalScope = PrincipalScope.Any

    /** Match any principal (default) */
    fun any() {
        scope = PrincipalScope.Any
    }

    /** Match only authenticated principals */
    fun authenticated() {
        scope = PrincipalScope.Authenticated
    }

    /** Match only anonymous principals */
    fun anonymous() {
        scope = PrincipalScope.Anonymous
    }

    // === Workspace Roles ===

    /** Match workspace admins */
    fun isWorkspaceAdmin() {
        scope = PrincipalScope.IsWorkspaceAdmin
    }

    /** Match workspace members (includes admins) */
    fun isWorkspaceMember() {
        scope = PrincipalScope.IsWorkspaceMember
    }

    // === Admin Roles ===

    /** Match principals who admin at least one community */
    fun isCommunityAdmin() {
        scope = PrincipalScope.IsCommunityAdmin
    }

    /** Match principals who admin at least one campaign */
    fun isCampaignAdmin() {
        scope = PrincipalScope.IsCampaignAdmin
    }

    // === Moderator Roles ===

    /** Match principals who moderate at least one community */
    fun isCommunityModerator() {
        scope = PrincipalScope.IsCommunityModerator
    }

    /** Match principals who moderate at least one campaign */
    fun isCampaignModerator() {
        scope = PrincipalScope.IsCampaignModerator
    }

    /** Match principals who moderate at least one group */
    fun isGroupModerator() {
        scope = PrincipalScope.IsGroupModerator
    }

    /** Match principals who moderate at least one custom field */
    fun isCustomFieldModerator() {
        scope = PrincipalScope.IsCustomFieldModerator
    }

    /** Match if all scopes match (AND) */
    fun all(vararg builders: PrincipalScopeBuilder.() -> Unit) {
        val scopes = builders.map { PrincipalScopeBuilder().apply(it).build() }
        scope = PrincipalScope.All(scopes)
    }

    /** Match if any scope matches (OR) */
    fun oneOf(vararg builders: PrincipalScopeBuilder.() -> Unit) {
        val scopes = builders.map { PrincipalScopeBuilder().apply(it).build() }
        scope = PrincipalScope.OneOf(scopes)
    }

    fun build(): PrincipalScope = scope
}

/**
 * DSL builder for ActionScope.
 *
 * Usage:
 * ```kotlin
 * action = { oneOf(Action.UPDATE, Action.DELETE) }
 * ```
 */
@CedarDslMarker
class ActionScopeBuilder {
    private var scope: ActionScope = ActionScope.Any

    /** Match any action (default) */
    fun any() {
        scope = ActionScope.Any
    }

    /** Match exact action */
    fun eq(action: Action) {
        scope = ActionScope.Exact(action)
    }

    /** Match any of the specified actions (2 actions) */
    fun oneOf(first: Action, second: Action) {
        scope = ActionScope.OneOf(setOf(first, second))
    }

    /** Match any of the specified actions (3 actions) */
    fun oneOf(first: Action, second: Action, third: Action) {
        scope = ActionScope.OneOf(setOf(first, second, third))
    }

    /** Match any of the specified actions */
    fun oneOf(actions: Set<Action>) {
        scope = ActionScope.OneOf(actions)
    }

    fun build(): ActionScope = scope
}

/**
 * DSL builder for ResourceScope.
 *
 * Usage:
 * ```kotlin
 * resource = {
 *     ofType(Resource.IDEA)
 * }
 * ```
 */
@CedarDslMarker
class ResourceScopeBuilder {
    private var scope: ResourceScope = ResourceScope.Any

    /** Match any resource (default) */
    fun any() {
        scope = ResourceScope.Any
    }

    /** Match resource of specific type */
    fun ofType(type: Resource) {
        scope = ResourceScope.OfType(type)
    }

    /** Match resource of any of specified types */
    fun ofTypes(vararg types: Resource) {
        scope = ResourceScope.OfTypes(types.toSet())
    }

    fun build(): ResourceScope = scope
}

/**
 * Marker annotation for Cedar DSL to enable scope control.
 */
@DslMarker
annotation class CedarDslMarker
