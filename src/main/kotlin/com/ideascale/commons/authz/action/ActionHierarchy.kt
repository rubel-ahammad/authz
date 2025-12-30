package com.ideascale.commons.authz.action

/**
 * Represents an item in the action hierarchy.
 * Can be either a leaf Action or a HierarchicalActionGroup.
 */
sealed interface ActionItem {
    val id: String
}

/**
 * Hierarchical action group that can contain actions or other groups.
 * Supports Cedar-style "action in Group" matching.
 *
 * Usage:
 * ```kotlin
 * object IdeaActions : HierarchicalActionGroup("idea") {
 *     val view = action("idea.view")
 *     val edit = action("idea.edit")
 *     val delete = action("idea.delete")
 *
 *     val readActions = group("idea.read", view)
 *     val writeActions = group("idea.write", edit, delete)
 * }
 * ```
 */
open class HierarchicalActionGroup(
    override val id: String,
    private val members: Set<ActionItem> = emptySet()
) : ActionItem {

    private val _registeredActions = mutableSetOf<Action>()
    private val _registeredGroups = mutableSetOf<HierarchicalActionGroup>()

    /**
     * All actions in this group (including nested groups).
     */
    val allActions: Set<Action> by lazy {
        val actions = mutableSetOf<Action>()
        actions.addAll(_registeredActions)
        actions.addAll(members.filterIsInstance<Action>())
        members.filterIsInstance<HierarchicalActionGroup>().forEach { group ->
            actions.addAll(group.allActions)
        }
        _registeredGroups.forEach { group ->
            actions.addAll(group.allActions)
        }
        actions.toSet()
    }

    /**
     * Check if this group contains the given action.
     */
    fun contains(action: Action): Boolean = action in allActions

    /**
     * Check if this group contains all actions from another group.
     */
    fun contains(group: HierarchicalActionGroup): Boolean =
        group.allActions.all { it in allActions }

    /**
     * Create and register an action in this group.
     */
    protected fun action(id: String): Action = Action(id).also {
        _registeredActions.add(it)
    }

    /**
     * Create a sub-group with the specified members.
     */
    protected fun group(id: String, vararg members: ActionItem): HierarchicalActionGroup =
        HierarchicalActionGroup(id, members.toSet()).also {
            _registeredGroups.add(it)
        }

    override fun toString(): String = "ActionGroup($id)"
}
