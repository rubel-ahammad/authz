package com.ideascale.authz.engine.evaluator

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.EvaluationStep
import com.ideascale.authz.engine.StepResult
import com.ideascale.authz.context.provider.AttributeContextProvider
import com.ideascale.authz.policy.rule.ActionClassifier
import com.ideascale.authz.policy.rule.RuleRegistry
import com.ideascale.authz.policy.rule.Target

class AttributeEvaluationStep(
    private val provider: AttributeContextProvider,
    private val registry: RuleRegistry,
    private val classifier: ActionClassifier
) : EvaluationStep {
    override fun evaluate(ctx: EvaluationContext): StepResult {
        val request = ctx.request
        val resourceContext = ctx.resourceContext
            ?: return StepResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingResourceContext"))
            )
        if (ctx.relationshipContext == null) {
            return StepResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingRelationshipContext"))
            )
        }

        val subject = request.subject

        val attributeContext = ctx.memoize("attributeContext") {
            provider.load(subject.workspaceId, subject.memberId, request.resource, resourceContext, request.context)
        }
        ctx.attributeContext = attributeContext

        val target = Target(request.resource.type, classifier.groupOf(request.action))
        for (rule in registry.deniesFor(target)) {
            val denyReason = rule.evaluate(ctx)
            if (denyReason != null) {
                return StepResult.Stop(
                    ctx.deny(
                        denyReason,
                        details = mapOf(
                            "deniedByLayer" to "ATTRIBUTE",
                            "deniedByRuleId" to rule.id
                        )
                    )
                )
            }
        }

        return StepResult.Continue
    }
}
