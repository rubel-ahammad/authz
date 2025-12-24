package com.ideascale.commons.authz.policy.evaluator

import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.context.provider.ResourceContextProvider
import com.ideascale.commons.authz.policy.rule.ActionClassifier
import com.ideascale.commons.authz.policy.rule.RuleRegistry
import com.ideascale.commons.authz.policy.rule.Target

class ResourceEvaluationStep(
    private val provider: ResourceContextProvider,
    private val registry: RuleRegistry,
    private val classifier: ActionClassifier
) : EvaluationStep {
    override fun evaluate(ctx: EvaluationContext): StepResult {
        val request = ctx.request
        val subject = request.subject
        val resource = request.resource

        val resourceContext = provider.load(resource)
        ctx.resourceContext = resourceContext

        if (resourceContext.workspaceId != subject.workspaceId) {
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
