package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.engine.EvalResult
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.policies.AuthorityPolicy
import com.ideascale.authz.engine.providers.AuthorityProvider

class AuthorityEvaluator(
    private val provider: AuthorityProvider,
    private val policy: AuthorityPolicy
) : com.ideascale.authz.engine.Evaluator {
    override fun evaluate(ctx: EvaluationContext): EvalResult {
        val subject = ctx.request.subject
        val resource = ctx.request.resource
        val rc = ctx.resourceContext
            ?: return EvalResult.Stop(
                ctx.deny(com.ideascale.authz.core.ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingResourceContext"))
            )
        val rf = ctx.relationshipFacts
            ?: return EvalResult.Stop(
                ctx.deny(com.ideascale.authz.core.ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingRelationshipFacts"))
            )

        val authorities = provider.load(subject.workspaceId, subject.memberId, resource, rc, rf)
        ctx.authorities = authorities

        val allowDecision = policy.allowDecisionIfMatched(ctx.request.action, resource, rc, rf, authorities)
        if (allowDecision != null) {
            return EvalResult.Stop(ctx.withBaseDetails(allowDecision))
        }

        return EvalResult.Continue
    }
}
