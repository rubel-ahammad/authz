package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvalResult
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.providers.AttributeProvider
import com.ideascale.authz.engine.rules.ActionClassifier
import com.ideascale.authz.engine.rules.RuleRegistry
import com.ideascale.authz.engine.rules.Target

class AttributeEvaluator(
    private val provider: AttributeProvider,
    private val registry: RuleRegistry,
    private val classifier: ActionClassifier
) : com.ideascale.authz.engine.Evaluator {
    override fun evaluate(ctx: EvaluationContext): EvalResult {
        val request = ctx.request
        val rc = ctx.resourceContext
            ?: return EvalResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingResourceContext"))
            )
        if (ctx.relationshipFacts == null) {
            return EvalResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingRelationshipFacts"))
            )
        }

        val subject = request.subject

        val attributeFacts = ctx.memoize("attributeFacts") {
            provider.load(subject.workspaceId, subject.memberId, request.resource, rc, request.context)
        }
        ctx.attributeFacts = attributeFacts

        val target = Target(request.resource.type, classifier.groupOf(request.action))
        for (rule in registry.deniesFor(target)) {
            val denyReason = rule.evaluate(ctx)
            if (denyReason != null) {
                return EvalResult.Stop(
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

        return EvalResult.Continue
    }
}
