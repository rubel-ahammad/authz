package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.engine.EvalResult
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.policies.AttributeConstraintPolicy
import com.ideascale.authz.engine.providers.AttributeProvider

class AttributeConstraintEvaluator(
    private val provider: AttributeProvider,
    private val policy: AttributeConstraintPolicy
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

        val af = provider.load(subject.workspaceId, subject.memberId, resource, rc)
        ctx.attributeFacts = af

        val denyReason = policy.denyReasonIfForbidden(ctx.request.action, resource, rc, rf, af)
        if (denyReason != null) {
            return EvalResult.Stop(ctx.deny(denyReason))
        }

        return EvalResult.Continue
    }
}
