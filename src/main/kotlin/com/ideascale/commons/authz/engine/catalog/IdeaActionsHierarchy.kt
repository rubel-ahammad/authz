package com.ideascale.commons.authz.engine.catalog

import com.ideascale.commons.authz.action.ActionGroupRegistry
import com.ideascale.commons.authz.action.ActionMetadataRegistry
import com.ideascale.commons.authz.action.HierarchicalActionGroup

/**
 * Hierarchical action definitions for Idea resources.
 *
 * Supports "action in Group" matching for policy definitions.
 *
 * Example usage:
 * ```kotlin
 * action = { `in`(IdeaActionsHierarchy.writeActions) }
 * action = { eq(IdeaActionsHierarchy.edit) }
 * ```
 */
object IdeaActionsHierarchy : HierarchicalActionGroup("idea") {

    // ========== Leaf Actions ==========

    val view = action("idea.view")
    val list = action("idea.list")
    val create = action("idea.create")
    val edit = action("idea.edit")
    val delete = action("idea.delete")

    // ========== Moderation Actions ==========

    object Moderate : HierarchicalActionGroup("idea.moderate") {
        val hide = action("idea.moderate.hide")
        val unhide = action("idea.moderate.unhide")
        val lock = action("idea.moderate.lock")
        val unlock = action("idea.moderate.unlock")
    }

    // ========== Hierarchical Groups ==========

    /** Read-only actions */
    val readActions = group("idea.read", view, list)

    /** Write/modify actions */
    val writeActions = group("idea.write", create, edit, delete)

    /** All moderation actions */
    val moderateActions = group(
        "idea.moderate.all",
        Moderate.hide,
        Moderate.unhide,
        Moderate.lock,
        Moderate.unlock
    )

    init {
        // Register groups for lookup by ID
        ActionGroupRegistry.register(this)
        ActionGroupRegistry.register(readActions)
        ActionGroupRegistry.register(writeActions)
        ActionGroupRegistry.register(moderateActions)
        ActionGroupRegistry.register(Moderate)

        // Register action metadata
        ActionMetadataRegistry.register(view) { read() }
        ActionMetadataRegistry.register(list) { read() }
        ActionMetadataRegistry.register(create) { write() }
        ActionMetadataRegistry.register(edit) { write() }
        ActionMetadataRegistry.register(delete) { write() }
        ActionMetadataRegistry.register(Moderate.hide) { write() }
        ActionMetadataRegistry.register(Moderate.unhide) { write() }
        ActionMetadataRegistry.register(Moderate.lock) { write() }
        ActionMetadataRegistry.register(Moderate.unlock) { write() }
    }
}
