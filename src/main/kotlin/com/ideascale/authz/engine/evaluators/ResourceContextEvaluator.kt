package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvalResult
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.providers.ResourceContextResolver
import com.ideascale.authz.engine.rules.ActionClassifier
import com.ideascale.authz.engine.rules.RuleRegistry
import com.ideascale.authz.engine.rules.Target

class ResourceContextEvaluator(
    private val resolver: ResourceContextResolver,
    private val registry: RuleRegistry,
    private val classifier: ActionClassifier
) : com.ideascale.authz.engine.Evaluator {
    override fun evaluate(ctx: EvaluationContext): EvalResult {
        val request = ctx.request
        val subject = request.subject
        val resource = request.resource

        val rc = resolver.resolve(resource)
        ctx.resourceContext = rc

        if (rc.workspaceId != subject.workspaceId) {
            return EvalResult.Stop(ctx.deny(ReasonCode.DENY_TENANT_MISMATCH))
        }

        val target = Target(resource.type, classifier.groupOf(request.action))
        for (rule in registry.deniesFor(target)) {
            val denyReason = rule.evaluate(ctx)
            if (denyReason != null) {
                return EvalResult.Stop(
                    ctx.deny(
                        denyReason,
                        details = mapOf(
                            "deniedByLayer" to "RESOURCE_CONTEXT",
                            "deniedByRuleId" to rule.id
                        )
                    )
                )
            }
        }

        return EvalResult.Continue
    }
}
