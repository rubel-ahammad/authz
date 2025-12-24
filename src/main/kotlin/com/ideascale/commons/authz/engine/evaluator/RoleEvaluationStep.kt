package com.ideascale.commons.authz.engine.evaluator

import com.ideascale.commons.authz.core.ReasonCode
import com.ideascale.commons.authz.engine.EvaluationContext
import com.ideascale.commons.authz.engine.EvaluationStep
import com.ideascale.commons.authz.engine.StepResult
import com.ideascale.commons.authz.context.provider.RoleContextProvider
import com.ideascale.commons.authz.policy.rule.ActionClassifier
import com.ideascale.commons.authz.policy.rule.RuleRegistry
import com.ideascale.commons.authz.policy.rule.Target

class RoleEvaluationStep(
    private val provider: RoleContextProvider,
    private val registry: RuleRegistry,
    private val classifier: ActionClassifier
) : EvaluationStep {
    override fun evaluate(ctx: EvaluationContext): StepResult {
        val request = ctx.request
        val resource = request.resource
        val resourceContext = ctx.resourceContext
            ?: return StepResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingResourceContext"))
            )
        val relationshipContext = ctx.relationshipContext
            ?: return StepResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingRelationshipContext"))
            )

        val subject = request.subject
        val roleContext = ctx.memoize("roleContext") {
            provider.load(subject.workspaceId, subject.memberId, resource, resourceContext, relationshipContext)
        }
        ctx.roleContext = roleContext

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
