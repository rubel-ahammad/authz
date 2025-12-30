package com.ideascale.commons.authz.engine

import com.ideascale.commons.authz.Authorizer
import com.ideascale.commons.authz.AuthorizationContext
import com.ideascale.commons.authz.Principal
import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.decision.Decision
import com.ideascale.commons.authz.engine.eval.PolicyEvaluator
import com.ideascale.commons.authz.engine.eval.PolicyIndex
import com.ideascale.commons.authz.engine.model.PolicySet
import com.ideascale.commons.authz.resource.Resource

/**
 * Authorizer implementation using the policy engine.
 *
 * This is a pure evaluation engine - no I/O, no data fetching.
 * The caller provides all context needed for authorization.
 *
 * Usage:
 * ```kotlin
 * // Build at startup
 * val index = PolicyIndex.build(WorkspacePolicies.toSet(), GlobalPolicies.toSet())
 * val authorizer = PolicyEngineAuthorizer(index)
 *
 * // Caller builds context with whatever data they have
 * val context = AuthorizationContext(
 *     roles = RoleContext(...),
 *     relationships = RelationshipContext(...),
 *     attributes = AttributeContext(...)
 * )
 *
 * // Authorize
 * val decision = authorizer.authorize(principal, action, resource, context)
 * ```
 */
class PolicyEngineAuthorizer(
    private val evaluator: PolicyEvaluator
) : Authorizer {

    /**
     * Create authorizer with a pre-built policy index.
     */
    constructor(index: PolicyIndex) : this(PolicyEvaluator.fromIndex(index))

    /**
     * Create authorizer from policy sets (builds index internally).
     */
    constructor(vararg policySets: PolicySet) : this(PolicyEvaluator.of(*policySets))

    override fun authorize(
        principal: Principal,
        action: Action,
        resource: Resource,
        context: AuthorizationContext
    ): Decision {
        return evaluator.evaluate(
            principal = principal,
            action = action,
            resource = resource,
            roleContext = context.roles,
            resourceContext = context.resource,
            relationshipContext = context.relationships,
            attributeContext = context.attributes
        )
    }

    /**
     * Get the underlying policy index.
     */
    fun index(): PolicyIndex = evaluator.index()

    companion object {
        /**
         * Create a builder for PolicyEngineAuthorizer.
         */
        fun builder() = PolicyEngineAuthorizerBuilder()
    }
}

/**
 * Builder for PolicyEngineAuthorizer.
 */
class PolicyEngineAuthorizerBuilder {
    private var index: PolicyIndex? = null
    private val policySets = mutableListOf<PolicySet>()

    fun withIndex(index: PolicyIndex) = apply {
        this.index = index
    }

    fun addPolicySet(policySet: PolicySet) = apply {
        policySets.add(policySet)
    }

    fun addPolicySets(vararg sets: PolicySet) = apply {
        policySets.addAll(sets)
    }

    fun build(): PolicyEngineAuthorizer {
        return if (index != null) {
            PolicyEngineAuthorizer(index!!)
        } else if (policySets.isNotEmpty()) {
            val builtIndex = PolicyIndex.build(policySets)
            PolicyEngineAuthorizer(builtIndex)
        } else {
            throw IllegalStateException("Either index or policy sets must be provided")
        }
    }
}
