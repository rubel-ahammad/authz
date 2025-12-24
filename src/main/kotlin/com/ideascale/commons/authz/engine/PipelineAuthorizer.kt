package com.ideascale.commons.authz.engine

import com.ideascale.commons.authz.core.Action
import com.ideascale.commons.authz.core.AuthzContext
import com.ideascale.commons.authz.core.Authorizer
import com.ideascale.commons.authz.core.Decision
import com.ideascale.commons.authz.core.ReasonCode
import com.ideascale.commons.authz.core.ResourceRef
import com.ideascale.commons.authz.core.Subject

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
