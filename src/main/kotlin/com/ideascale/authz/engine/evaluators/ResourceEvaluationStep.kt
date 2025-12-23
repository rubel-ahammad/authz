package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.EvaluationStep
import com.ideascale.authz.engine.StepResult
import com.ideascale.authz.engine.providers.ResourceContextProvider
import com.ideascale.authz.engine.rules.ActionClassifier
import com.ideascale.authz.engine.rules.RuleRegistry
import com.ideascale.authz.engine.rules.Target

class ResourceEvaluationStep(
    private val provider: ResourceContextProvider,
    private val registry: RuleRegistry,
    private val classifier: ActionClassifier
) : EvaluationStep {
    override fun evaluate(ctx: EvaluationContext): StepResult {
        val request = ctx.request
        val subject = request.subject
        val resource = request.resource

        val contextFacts = provider.load(resource)
        ctx.contextFacts = contextFacts

        if (contextFacts.workspaceId != subject.workspaceId) {
            return StepResult.Stop(ctx.deny(ReasonCode.DENY_TENANT_MISMATCH))
        }

        val target = Target(resource.type, classifier.groupOf(request.action))
        for (rule in registry.deniesFor(target)) {
            val denyReason = rule.evaluate(ctx)
            if (denyReason != null) {
                return StepResult.Stop(
                    ctx.deny(
                        denyReason,
                        details = mapOf(
                            "deniedByLayer" to "RESOURCE_CONTEXT",
                            "deniedByRuleId" to rule.id
                        )
                    )
                )
            }
        }

        return StepResult.Continue
    }
}
