package com.ideascale.authz.policy.catalog

import com.ideascale.authz.core.ActionGroup
import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.policy.dsl.deny
import com.ideascale.authz.policy.rule.DenyRule

object GlobalRules {
    fun attributeDenyRules(): List<DenyRule> = listOf(
        denyWritesWhenWorkspaceReadOnly()
    )

    private fun denyWritesWhenWorkspaceReadOnly(): DenyRule =
        deny {
            id("global.workspace.readonly.deny_write")
            global(ActionGroup.WRITE)
            condition { ec: EvaluationContext ->
                val facts = ec.attributeContext ?: return@condition null
                if (facts.workspace.flags.isReadOnlyMode) ReasonCode.DENY_WORKSPACE_READONLY else null
            }
        }
}
