package com.ideascale.commons.authz.action

import com.ideascale.commons.authz.engine.catalog.IdeaActionsHierarchy
import com.ideascale.commons.authz.engine.catalog.WorkspaceActionsHierarchy
import kotlin.test.Test
import kotlin.test.assertTrue

class ActionMetadataRegistryTest {

    @Test
    fun `all registered actions have metadata`() {
        // Ensure action hierarchies are initialized
        IdeaActionsHierarchy.view
        WorkspaceActionsHierarchy.read

        val actions = ActionGroupRegistry.all()
            .flatMap { it.allActions }
            .toSet()

        val missing = actions.filter { ActionMetadataRegistry.get(it.id) == null }
        assertTrue(
            missing.isEmpty(),
            "Missing metadata for actions: ${missing.map { it.id }}"
        )
    }
}
