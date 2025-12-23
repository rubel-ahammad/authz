package com.ideascale.authz.engine

import com.ideascale.authz.core.Decision

sealed interface StepResult {
    data object Continue : StepResult
    data class Stop(val decision: Decision) : StepResult
}

fun interface EvaluationStep {
    fun evaluate(ctx: EvaluationContext): StepResult
}
