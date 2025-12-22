package com.ideascale.authz.engine

import com.ideascale.authz.core.Decision

sealed interface EvalResult {
    data object Continue : EvalResult
    data class Stop(val decision: Decision) : EvalResult
}

fun interface Evaluator {
    fun evaluate(ctx: EvaluationContext): EvalResult
}
