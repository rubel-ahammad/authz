package com.ideascale.commons.authz.engine.model

import com.ideascale.commons.authz.decision.ReasonCode

/**
 * A Cedar-style authorization policy.
 *
 * A policy defines:
 * - Effect: PERMIT or FORBID
 * - Scope: Who (principal), what action, on which resource
 * - Conditions: Additional constraints that must be true (when) or false (unless)
 *
 * Cedar evaluation semantics:
 * - FORBID always overrides PERMIT
 * - Default is DENY if no policy matches
 *
 * @param id Unique identifier for audit/debug
 * @param effect PERMIT or FORBID
 * @param scope Principal/Action/Resource scope for matching
 * @param whenConditions Conditions that must ALL be true for policy to apply (implicit AND)
 * @param unlessConditions If ANY is true, policy does not apply (for FORBID policies)
 * @param reasonCode Reason code for Decision audit trail
 * @param priority Lower number = higher priority (evaluated first)
 * @param description Human-readable description for documentation
 */
data class Policy(
    val id: String,
    val effect: PolicyEffect,
    val scope: PolicyScope,
    val whenConditions: List<PolicyCondition> = emptyList(),
    val unlessConditions: List<PolicyCondition> = emptyList(),
    val reasonCode: ReasonCode,
    val priority: Int = DEFAULT_PRIORITY,
    val description: String? = null
) {
    companion object {
        const val DEFAULT_PRIORITY = 100
        const val HIGH_PRIORITY = 10
        const val LOW_PRIORITY = 1000
    }

    /**
     * Check if all 'when' conditions are satisfied.
     */
    fun whenConditionsSatisfied(ctx: ConditionContext): Boolean =
        whenConditions.isEmpty() || whenConditions.all { it.evaluate(ctx) }

    /**
     * Check if any 'unless' condition is satisfied (policy should NOT apply).
     */
    fun unlessConditionsSatisfied(ctx: ConditionContext): Boolean =
        unlessConditions.isNotEmpty() && unlessConditions.any { it.evaluate(ctx) }

    /**
     * Check if all conditions are satisfied for this policy to apply.
     */
    fun conditionsSatisfied(ctx: ConditionContext): Boolean =
        whenConditionsSatisfied(ctx) && !unlessConditionsSatisfied(ctx)
}
