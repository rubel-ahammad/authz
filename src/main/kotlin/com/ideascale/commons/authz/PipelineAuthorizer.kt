package com.ideascale.commons.authz

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.AuthzContext
import com.ideascale.commons.authz.Authorizer
import com.ideascale.commons.authz.decision.Decision
import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.resource.ResourceRef
import com.ideascale.commons.authz.Subject

class PipelineAuthorizer internal constructor(
    private val steps: List<EvaluationStep>
) : Authorizer {
    override fun authorize(
        subject: Subject,
        action: Action,
        resource: ResourceRef,
        context: AuthzContext
    ): Decision {
        val request = AuthzRequest(subject, action, resource, context)
        val evalCtx = EvaluationContext(request)

        for (step in steps) {
            when (val result = step.evaluate(evalCtx)) {
                is StepResult.Continue -> Unit
                is StepResult.Stop -> return evalCtx.withBaseDetails(result.decision)
            }
        }

        return evalCtx.deny(ReasonCode.DENY_DEFAULT)
    }
}
