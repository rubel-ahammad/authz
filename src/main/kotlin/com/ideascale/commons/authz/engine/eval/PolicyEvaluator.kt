package com.ideascale.commons.authz.engine.eval

import com.ideascale.commons.authz.Subject
import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.engine.model.*
import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.decision.Decision
import com.ideascale.commons.authz.decision.Effect
import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.resource.ResourceRef

/**
 * Result of evaluating a single policy.
 */
sealed interface PolicyEvalResult {
    /** Policy scope doesn't match the request */
    data object NotApplicable : PolicyEvalResult

    /** Policy matches and its effect applies */
    data class Applicable(
        val policy: Policy,
        val effect: PolicyEffect
    ) : PolicyEvalResult
}

/**
 * Policy evaluator with efficient index-based lookup.
 *
 * Evaluation semantics:
 * 1. Find all policies that match the request scope (using index for efficiency)
 * 2. Evaluate conditions for matching policies
 * 3. If ANY forbid policy applies -> DENY (forbid overrides permit)
 * 4. If ANY permit policy applies -> ALLOW
 * 5. Otherwise -> DENY (default deny)
 *
 * @param index Pre-built policy index for efficient lookup
 */
class PolicyEvaluator private constructor(
    private val index: PolicyIndex
) {
    /**
     * Create evaluator from policy sets (builds index internally).
     */
    constructor(policySets: List<PolicySet>) : this(PolicyIndex.build(policySets))

    /**
     * Evaluate all policies against the request.
     */
    fun evaluate(
        subject: Subject,
        action: Action,
        resource: ResourceRef,
        roleContext: RoleContext? = null,
        resourceContext: ResourceContext? = null,
        relationshipContext: RelationshipContext? = null,
        attributeContext: AttributeContext? = null
    ): Decision {
        val conditionContext = ConditionContext(
            roleContext = roleContext,
            resourceContext = resourceContext,
            relationshipContext = relationshipContext,
            attributeContext = attributeContext
        )

        // Use index for efficient policy lookup
        val candidatePolicies = index.getPoliciesFor(resource.type, action)

        val applicablePolicies = findApplicablePolicies(
            candidatePolicies, subject, action, resource, roleContext, conditionContext
        )

        // Forbid overrides permit - check forbids first
        val forbids = applicablePolicies.filter { it.effect == PolicyEffect.FORBID }
        if (forbids.isNotEmpty()) {
            val firstForbid = forbids.first()
            return Decision(
                effect = Effect.DENY,
                reason = firstForbid.reasonCode,
                details = mapOf(
                    "matchedPolicyId" to firstForbid.id,
                    "evaluator" to "policy_engine",
                    "matchType" to "forbid"
                )
            )
        }

        // Check for permit
        val permits = applicablePolicies.filter { it.effect == PolicyEffect.PERMIT }
        if (permits.isNotEmpty()) {
            val firstPermit = permits.first()
            return Decision(
                effect = Effect.ALLOW,
                reason = firstPermit.reasonCode,
                details = mapOf(
                    "matchedPolicyId" to firstPermit.id,
                    "evaluator" to "policy_engine",
                    "matchType" to "permit"
                )
            )
        }

        // Default deny
        return Decision(
            effect = Effect.DENY,
            reason = ReasonCode.DENY_DEFAULT,
            details = mapOf(
                "evaluator" to "policy_engine",
                "matchType" to "no_matching_policy"
            )
        )
    }

    /**
     * Evaluate a single policy against the request.
     */
    fun evaluatePolicy(
        policy: Policy,
        subject: Subject,
        action: Action,
        resource: ResourceRef,
        roleContext: RoleContext?,
        conditionContext: ConditionContext
    ): PolicyEvalResult {
        // Check scope match
        val scopeMatches = ScopeMatcher.matches(
            subject, action, resource, roleContext, policy.scope
        )

        if (!scopeMatches) {
            return PolicyEvalResult.NotApplicable
        }

        // Check conditions
        if (!policy.conditionsSatisfied(conditionContext)) {
            return PolicyEvalResult.NotApplicable
        }

        return PolicyEvalResult.Applicable(policy, policy.effect)
    }

    /**
     * Get the underlying policy index.
     */
    fun index(): PolicyIndex = index

    private fun findApplicablePolicies(
        candidates: List<Policy>,
        subject: Subject,
        action: Action,
        resource: ResourceRef,
        roleContext: RoleContext?,
        conditionContext: ConditionContext
    ): List<Policy> {
        return candidates.mapNotNull { policy ->
            val result = evaluatePolicy(
                policy, subject, action, resource, roleContext, conditionContext
            )
            when (result) {
                is PolicyEvalResult.Applicable -> policy
                is PolicyEvalResult.NotApplicable -> null
            }
        }
    }

    companion object {
        /**
         * Create a builder for PolicyEvaluator.
         */
        fun builder() = PolicyEvaluatorBuilder()

        /**
         * Create evaluator from policy sets.
         */
        fun of(vararg policySets: PolicySet) = PolicyEvaluator(policySets.toList())

        /**
         * Create evaluator from a pre-built index.
         * Use this for optimal performance when the index is built at startup.
         */
        fun fromIndex(index: PolicyIndex) = PolicyEvaluator(index)
    }
}

/**
 * Builder for PolicyEvaluator.
 */
class PolicyEvaluatorBuilder {
    private val policySets = mutableListOf<PolicySet>()
    private var prebuiltIndex: PolicyIndex? = null

    fun addPolicySet(policySet: PolicySet): PolicyEvaluatorBuilder = apply {
        policySets.add(policySet)
    }

    fun addPolicySets(vararg sets: PolicySet): PolicyEvaluatorBuilder = apply {
        policySets.addAll(sets)
    }

    fun addPolicySets(sets: List<PolicySet>): PolicyEvaluatorBuilder = apply {
        policySets.addAll(sets)
    }

    /**
     * Use a pre-built index instead of building one from policy sets.
     */
    fun withIndex(index: PolicyIndex): PolicyEvaluatorBuilder = apply {
        prebuiltIndex = index
    }

    fun build(): PolicyEvaluator {
        return prebuiltIndex?.let { PolicyEvaluator.fromIndex(it) }
            ?: PolicyEvaluator(policySets.toList())
    }
}
