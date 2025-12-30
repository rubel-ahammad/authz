package com.ideascale.commons.authz.engine.catalog

import com.ideascale.commons.authz.action.ActionGroupRegistry
import com.ideascale.commons.authz.action.ActionMetadataRegistry
import com.ideascale.commons.authz.action.HierarchicalActionGroup

/**
 * Hierarchical action definitions for Workspace resources.
 */
object WorkspaceActionsHierarchy : HierarchicalActionGroup("workspace") {

    // ========== Leaf Actions ==========

    val read = action("workspace.read")
    val update = action("workspace.update")

    // ========== Hierarchical Groups ==========

    /** Read-only actions */
    val readActions = group("workspace.read.all", read)

    /** Write/modify actions */
    val writeActions = group("workspace.write", update)

    init {
        ActionGroupRegistry.register(this)
        ActionGroupRegistry.register(readActions)
        ActionGroupRegistry.register(writeActions)

        ActionMetadataRegistry.register(read) { read() }
        ActionMetadataRegistry.register(update) { write() }
    }
}
