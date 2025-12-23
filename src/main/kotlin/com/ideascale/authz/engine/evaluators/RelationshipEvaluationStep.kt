package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.EvaluationStep
import com.ideascale.authz.engine.StepResult
import com.ideascale.authz.context.providers.RelationshipContextProvider
import com.ideascale.authz.policy.rules.ActionClassifier
import com.ideascale.authz.policy.rules.RuleRegistry
import com.ideascale.authz.policy.rules.Target

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

        if (!relationshipContext.isWorkspaceMember) {
            return StepResult.Stop(ctx.deny(ReasonCode.DENY_NOT_IN_SCOPE))
        }

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
