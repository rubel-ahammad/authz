package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvalResult
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.providers.RelationshipProvider
import com.ideascale.authz.engine.rules.ActionClassifier
import com.ideascale.authz.engine.rules.RuleRegistry
import com.ideascale.authz.engine.rules.Target

class RelationshipEvaluator(
    private val provider: RelationshipProvider,
    private val registry: RuleRegistry,
    private val classifier: ActionClassifier
) : com.ideascale.authz.engine.Evaluator {
    override fun evaluate(ctx: EvaluationContext): EvalResult {
        val request = ctx.request
        val subject = request.subject
        val resource = request.resource
        val rc = ctx.resourceContext
            ?: return EvalResult.Stop(
                ctx.deny(ReasonCode.DENY_DEFAULT, details = mapOf("error" to "missingResourceContext"))
            )

        val rf = provider.load(subject.workspaceId, subject.memberId, resource, rc)
        ctx.relationshipFacts = rf

        if (!rf.isWorkspaceMember) {
            return EvalResult.Stop(ctx.deny(ReasonCode.DENY_NOT_IN_SCOPE))
        }

        val target = Target(resource.type, classifier.groupOf(request.action))
        for (rule in registry.deniesFor(target)) {
            val denyReason = rule.evaluate(ctx)
            if (denyReason != null) {
                return EvalResult.Stop(
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

        return EvalResult.Continue
    }
}
