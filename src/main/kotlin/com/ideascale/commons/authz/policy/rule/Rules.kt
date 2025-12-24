package com.ideascale.commons.authz.policy.rule

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.action.ActionGroup
import com.ideascale.commons.authz.decision.Decision
import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.resource.ResourceType
import com.ideascale.commons.authz.action.ActionSemantics
import com.ideascale.commons.authz.EvaluationContext

fun interface ActionClassifier {
    fun groupOf(action: Action): ActionGroup
}

object DefaultActionClassifier : ActionClassifier {
    override fun groupOf(action: Action): ActionGroup = ActionSemantics.groupOf(action)
}

data class Target(val resourceType: ResourceType?, val actionGroup: ActionGroup) {
    companion object {
        fun global(actionGroup: ActionGroup) = Target(null, actionGroup)
    }
}

class DenyRule(
    val id: String,
    val target: Target,
    val evaluate: (EvaluationContext) -> ReasonCode?
)

class AllowRule(
    val id: String,
    val target: Target,
    val evaluate: (EvaluationContext) -> Decision?
)

class RuleRegistry(
    denyRules: List<DenyRule>,
    allowRules: List<AllowRule>
) {
    private val deniesByTarget: Map<Target, List<DenyRule>> = denyRules.groupBy { it.target }
    private val allowsByTarget: Map<Target, List<AllowRule>> = allowRules.groupBy { it.target }

    fun deniesFor(target: Target): List<DenyRule> =
        deniesByTarget[Target.global(target.actionGroup)].orEmpty() + deniesByTarget[target].orEmpty()

    fun allowsFor(target: Target): List<AllowRule> =
        allowsByTarget[Target.global(target.actionGroup)].orEmpty() + allowsByTarget[target].orEmpty()
}
