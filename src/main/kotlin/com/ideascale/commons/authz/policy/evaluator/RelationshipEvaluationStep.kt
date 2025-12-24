package com.ideascale.commons.authz.policy.evaluator

import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.context.provider.RelationshipContextProvider
import com.ideascale.commons.authz.policy.rule.ActionClassifier
import com.ideascale.commons.authz.policy.rule.RuleRegistry
import com.ideascale.commons.authz.policy.rule.Target

class RelationshipEvaluationStep(
    private val provider: RelationshipContextProvider,
    private val registry: RuleRegistry,
    private val classifier: ActionClassifier
) : EvaluationStep {
    override fun evaluate(ctx: EvaluationContext): StepResult {
        val request = ctx.request
        val subject = request.subject
        val resource = request.resource
        val resourceContext = ctx.resourceContext
            ?: return StepResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingResourceContext"))
            )

        val relationshipContext = provider.load(subject.workspaceId, subject.memberId, resource, resourceContext)
        ctx.relationshipContext = relationshipContext

        val target = Target(resource.type, classifier.groupOf(request.action))
        for (rule in registry.deniesFor(target)) {
            val denyReason = rule.evaluate(ctx)
            if (denyReason != null) {
                return StepResult.Stop(
                    ctx.deny(
                        denyReason,
                        details = mapOf(
                            "deniedByLayer" to "RELATIONSHIP",
                            "deniedByRuleId" to rule.id
                        )
                    )
                )
            }
        }

        return StepResult.Continue
    }
}
