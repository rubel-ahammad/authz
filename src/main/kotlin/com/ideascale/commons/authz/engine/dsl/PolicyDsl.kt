package com.ideascale.commons.authz.engine.dsl

import com.ideascale.commons.authz.engine.model.*
import com.ideascale.commons.authz.decision.Obligation
import com.ideascale.commons.authz.decision.ReasonCode

/**
 * Create a PERMIT policy.
 *
 * Usage:
 * ```kotlin
 * permit(
 *     principal = { hasRole(RoleIds.WORKSPACE_ADMIN) },
 *     action = { oneOf(Action.UPDATE, Action.DELETE) },
 *     resource = { ofType(Resource.IDEA) }
 * )
 * ```
 */
fun permit(
    principal: PrincipalScopeBuilder.() -> Unit = { any() },
    action: ActionScopeBuilder.() -> Unit = { any() },
    resource: ResourceScopeBuilder.() -> Unit = { any() }
): PolicyBuilder = PolicyBuilder(PolicyEffect.PERMIT).apply {
    principal(principal)
    action(action)
    resource(resource)
}

/**
 * Create a FORBID policy.
 *
 * Usage:
 * ```kotlin
 * forbid(
 *     principal = { any() },
 *     action = { oneOf(Action.UPDATE, Action.DELETE) },
 *     resource = { any() }
 * ) `when` {
 *     attribute { ideaState(IdeaState.LOCKED) }
 * }
 * ```
 */
fun forbid(
    principal: PrincipalScopeBuilder.() -> Unit = { any() },
    action: ActionScopeBuilder.() -> Unit = { any() },
    resource: ResourceScopeBuilder.() -> Unit = { any() }
): PolicyBuilder = PolicyBuilder(PolicyEffect.FORBID).apply {
    principal(principal)
    action(action)
    resource(resource)
}

/**
 * Builder for constructing a Policy.
 */
@CedarDslMarker
class PolicyBuilder(private val effect: PolicyEffect) {
    private var id: String? = null
    private var principalScope: PrincipalScope = PrincipalScope.Any
    private var actionScope: ActionScope = ActionScope.Any
    private var resourceScope: ResourceScope = ResourceScope.Any
    private val whenConditions = mutableListOf<PolicyCondition>()
    private val unlessConditions = mutableListOf<PolicyCondition>()
    private var reasonCode: ReasonCode? = null
    private val obligations = mutableSetOf<Obligation>()
    private var priority: Int = Policy.DEFAULT_PRIORITY
    private var description: String? = null

    /**
     * Set policy ID.
     */
    fun id(value: String): PolicyBuilder = apply { id = value }

    /**
     * Set principal scope.
     */
    fun principal(init: PrincipalScopeBuilder.() -> Unit) {
        principalScope = PrincipalScopeBuilder().apply(init).build()
    }

    /**
     * Set action scope.
     */
    fun action(init: ActionScopeBuilder.() -> Unit) {
        actionScope = ActionScopeBuilder().apply(init).build()
    }

    /**
     * Set resource scope.
     */
    fun resource(init: ResourceScopeBuilder.() -> Unit) {
        resourceScope = ResourceScopeBuilder().apply(init).build()
    }

    /**
     * Add 'when' conditions - all must be true for policy to apply.
     */
    infix fun `when`(init: ConditionBuilder.() -> Unit): PolicyBuilder = apply {
        whenConditions.addAll(ConditionBuilder().apply(init).build())
    }

    /**
     * Add 'unless' conditions - if any is true, policy does not apply.
     * Typically used with forbid policies.
     */
    infix fun unless(init: ConditionBuilder.() -> Unit): PolicyBuilder = apply {
        unlessConditions.addAll(ConditionBuilder().apply(init).build())
    }

    /**
     * Set reason code for audit trail.
     */
    fun reason(code: ReasonCode): PolicyBuilder = apply { reasonCode = code }

    /**
     * Add obligations to apply when this policy is the winner.
     */
    fun obligations(vararg values: Obligation): PolicyBuilder = apply {
        obligations.addAll(values)
    }

    /**
     * Add obligations to apply when this policy is the winner.
     */
    fun obligations(values: Set<Obligation>): PolicyBuilder = apply {
        obligations.addAll(values)
    }

    /**
     * Set priority (lower = higher priority).
     */
    fun priority(value: Int): PolicyBuilder = apply { priority = value }

    /**
     * Set description for documentation.
     */
    fun description(value: String): PolicyBuilder = apply { description = value }

    /**
     * Build the Policy.
     */
    fun build(): Policy {
        val finalId = id ?: "${effect.name.lowercase()}-${System.nanoTime()}"
        val finalReasonCode = reasonCode ?: when (effect) {
            PolicyEffect.PERMIT -> ReasonCode.ALLOW_SYSTEM
            PolicyEffect.FORBID -> ReasonCode.DENY_DEFAULT
        }

        return Policy(
            id = finalId,
            effect = effect,
            scope = PolicyScope(principalScope, actionScope, resourceScope),
            whenConditions = whenConditions.toList(),
            unlessConditions = unlessConditions.toList(),
            reasonCode = finalReasonCode,
            obligations = obligations.toSet(),
            priority = priority,
            description = description
        )
    }
}
