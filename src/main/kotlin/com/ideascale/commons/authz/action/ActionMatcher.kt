package com.ideascale.commons.authz.action

import com.ideascale.commons.authz.engine.model.ActionScope

/**
 * Utility for matching actions against action scopes.
 */
object ActionMatcher {

    /**
     * Check if an action matches the given scope.
     */
    fun matches(action: Action, scope: ActionScope): Boolean = when (scope) {
        is ActionScope.Any -> true
        is ActionScope.Exact -> action == scope.action
        is ActionScope.Write -> ActionMetadataRegistry.isWrite(action.id)
        is ActionScope.InGroup -> matchesGroup(action, scope.groupId)
        is ActionScope.OneOf -> scope.actions.any { it == action }
    }

    /**
     * Check if an action belongs to a group by group ID.
     * Uses the ActionGroupRegistry to resolve group IDs.
     */
    private fun matchesGroup(action: Action, groupId: String): Boolean {
        val group = ActionGroupRegistry.get(groupId) ?: return false
        return group.contains(action)
    }
}

/**
 * Global registry for action groups.
 * Allows looking up groups by ID for scope matching.
 */
object ActionGroupRegistry {
    private val groups = mutableMapOf<String, HierarchicalActionGroup>()

    /**
     * Register an action group.
     */
    fun register(group: HierarchicalActionGroup) {
        groups[group.id] = group
    }

    /**
     * Get an action group by ID.
     */
    fun get(id: String): HierarchicalActionGroup? = groups[id]

    /**
     * Get all registered groups.
     */
    fun all(): Collection<HierarchicalActionGroup> = groups.values

    /**
     * Clear all registrations (for testing).
     */
    fun clear() {
        groups.clear()
    }
}
