package com.ideascale.authz.engine

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.AuthzContext
import com.ideascale.authz.core.Authorizer
import com.ideascale.authz.core.Decision
import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.core.Subject

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
