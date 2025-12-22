package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvalResult
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.providers.ResourceContextResolver

class ResourceContextEvaluator(
    private val resolver: ResourceContextResolver
) : com.ideascale.authz.engine.Evaluator {
    override fun evaluate(ctx: EvaluationContext): EvalResult {
        val subject = ctx.request.subject
        val resource = ctx.request.resource

        val rc = resolver.resolve(resource)
        ctx.resourceContext = rc

        if (rc.workspaceId != subject.workspaceId) {
            return EvalResult.Stop(ctx.deny(ReasonCode.DENY_TENANT_MISMATCH))
        }

        return EvalResult.Continue
    }
}
