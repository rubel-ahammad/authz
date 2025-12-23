package com.ideascale.authz.policy.defaults

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.core.ActionGroup
import com.ideascale.authz.policy.rules.DenyRule
import com.ideascale.authz.policy.rules.Target

object GlobalRules {
    fun attributeDenyRules(): List<DenyRule> = listOf(
        denyWritesWhenWorkspaceReadOnly()
    )

    private fun denyWritesWhenWorkspaceReadOnly(): DenyRule =
        DenyRule(
            id = "global.workspace.readonly.deny_write",
            target = Target.global(ActionGroup.WRITE)
        ) { ec: EvaluationContext ->
            val facts = ec.attributeContext ?: return@DenyRule null
            if (facts.workspace.flags.isReadOnlyMode) ReasonCode.DENY_WORKSPACE_READONLY else null
        }
}
