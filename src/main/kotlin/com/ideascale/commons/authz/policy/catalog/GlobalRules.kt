package com.ideascale.commons.authz.policy.catalog

import com.ideascale.commons.authz.core.ActionGroup
import com.ideascale.commons.authz.core.ReasonCode
import com.ideascale.commons.authz.engine.EvaluationContext
import com.ideascale.commons.authz.policy.dsl.deny
import com.ideascale.commons.authz.policy.rule.DenyRule

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
