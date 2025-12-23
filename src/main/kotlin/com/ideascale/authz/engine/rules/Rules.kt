package com.ideascale.authz.engine.rules

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.Decision
import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.core.ResourceType
import com.ideascale.authz.engine.EvaluationContext

enum class ActionGroup { READ, WRITE, MODERATE, ADMIN }

fun interface ActionClassifier {
    fun groupOf(action: Action): ActionGroup
}

object DefaultActionClassifier : ActionClassifier {
    override fun groupOf(action: Action): ActionGroup {
        val id = action.id
        return when {
            id.contains(".moderate.") -> ActionGroup.MODERATE
            id.endsWith(".create") || id.endsWith(".edit") || id.endsWith(".update") || id.endsWith(".delete") ->
                ActionGroup.WRITE
            id.contains(".admin.") || id.contains(".settings.") || id.contains(".manage.") ->
                ActionGroup.ADMIN
            else -> ActionGroup.READ
        }
    }
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
