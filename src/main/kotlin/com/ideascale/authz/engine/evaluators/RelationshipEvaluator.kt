package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvalResult
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.providers.RelationshipProvider

class RelationshipEvaluator(
    private val provider: RelationshipProvider
) : com.ideascale.authz.engine.Evaluator {
    override fun evaluate(ctx: EvaluationContext): EvalResult {
        val subject = ctx.request.subject
        val resource = ctx.request.resource
        val rc = ctx.resourceContext
            ?: return EvalResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingResourceContext"))
            )

        val rf = provider.load(subject.workspaceId, subject.memberId, resource, rc)
        ctx.relationshipFacts = rf

        if (!rf.isWorkspaceMember) {
            return EvalResult.Stop(ctx.deny(ReasonCode.DENY_NOT_IN_SCOPE))
        }

        return EvalResult.Continue
    }
}
