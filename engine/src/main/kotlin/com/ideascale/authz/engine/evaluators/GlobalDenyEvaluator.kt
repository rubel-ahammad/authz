package com.ideascale.authz.engine.evaluators

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.engine.EvalResult
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.providers.GlobalDenyProvider

class GlobalDenyEvaluator(
    private val provider: GlobalDenyProvider
) : com.ideascale.authz.engine.Evaluator {
    override fun evaluate(ctx: EvaluationContext): EvalResult {
        val subject = ctx.request.subject
        val context = ctx.request.context

        if (provider.isBanned(subject.workspaceId, subject.memberId)) {
            return EvalResult.Stop(ctx.deny(ReasonCode.DENY_BANNED))
        }
        if (provider.isPending(subject.workspaceId, subject.memberId)) {
            return EvalResult.Stop(ctx.deny(ReasonCode.DENY_PENDING))
        }
        if (provider.isSubscriptionBlocked(subject.workspaceId)) {
            return EvalResult.Stop(ctx.deny(ReasonCode.DENY_SUBSCRIPTION_BLOCKED))
        }
        if (!provider.isIpAllowed(subject.workspaceId, context.ip, context.channel)) {
            return EvalResult.Stop(ctx.deny(ReasonCode.DENY_IP_RESTRICTED))
        }

        return EvalResult.Continue
    }
}
