package com.ideascale.commons.authz.policy.evaluator

import com.ideascale.commons.authz.decision.Decision

sealed interface StepResult {
    data object Continue : StepResult
    data class Stop(val decision: Decision) : StepResult
}

fun interface EvaluationStep {
    fun evaluate(ctx: EvaluationContext): StepResult
}
