package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvalResult
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.providers.AuthorityProvider
import com.ideascale.authz.engine.rules.ActionClassifier
import com.ideascale.authz.engine.rules.RuleRegistry
import com.ideascale.authz.engine.rules.Target

class AuthorityEvaluator(
    private val provider: AuthorityProvider,
    private val registry: RuleRegistry,
    private val classifier: ActionClassifier
) : com.ideascale.authz.engine.Evaluator {
    override fun evaluate(ctx: EvaluationContext): EvalResult {
        val request = ctx.request
        val resource = request.resource
        val rc = ctx.resourceContext
            ?: return EvalResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingResourceContext"))
            )
        val rf = ctx.relationshipFacts
            ?: return EvalResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingRelationshipFacts"))
            )

        val subject = request.subject
        val authorities = ctx.memoize("authorities") {
            provider.load(subject.workspaceId, subject.memberId, resource, rc, rf)
        }
        ctx.authorities = authorities

        val target = Target(resource.type, classifier.groupOf(request.action))
        for (rule in registry.allowsFor(target)) {
            val allowDecision = rule.evaluate(ctx)
            if (allowDecision != null) {
                val enriched = allowDecision.copy(
                    details = allowDecision.details + mapOf(
                        "allowedByLayer" to "AUTHORITY",
                        "allowedByRuleId" to rule.id
                    )
                )
                return EvalResult.Stop(ctx.withBaseDetails(enriched))
            }
        }

        return EvalResult.Continue
    }
}
