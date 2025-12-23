package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.EvaluationStep
import com.ideascale.authz.engine.StepResult
import com.ideascale.authz.engine.providers.RoleProvider
import com.ideascale.authz.engine.rules.ActionClassifier
import com.ideascale.authz.engine.rules.RuleRegistry
import com.ideascale.authz.engine.rules.Target

class RoleEvaluationStep(
    private val provider: RoleProvider,
    private val registry: RuleRegistry,
    private val classifier: ActionClassifier
) : EvaluationStep {
    override fun evaluate(ctx: EvaluationContext): StepResult {
        val request = ctx.request
        val resource = request.resource
        val contextFacts = ctx.contextFacts
            ?: return StepResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingContextFacts"))
            )
        val relationshipFacts = ctx.relationshipFacts
            ?: return StepResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingRelationshipFacts"))
            )

        val subject = request.subject
        val roleFacts = ctx.memoize("roleFacts") {
            provider.load(subject.workspaceId, subject.memberId, resource, contextFacts, relationshipFacts)
        }
        ctx.roleFacts = roleFacts

        val target = Target(resource.type, classifier.groupOf(request.action))
        for (rule in registry.allowsFor(target)) {
            val allowDecision = rule.evaluate(ctx)
            if (allowDecision != null) {
                val enriched = allowDecision.copy(
                    details = allowDecision.details + mapOf(
                        "allowedByLayer" to "ROLE",
                        "allowedByRuleId" to rule.id
                    )
                )
                return StepResult.Stop(ctx.withBaseDetails(enriched))
            }
        }

        return StepResult.Continue
    }
}
