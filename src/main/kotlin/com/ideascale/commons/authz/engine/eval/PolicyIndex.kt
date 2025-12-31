package com.ideascale.commons.authz.engine.eval

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.engine.model.*
import com.ideascale.commons.authz.resource.Resource

/**
 * Index for efficient policy lookup during authorization evaluation.
 *
 * The index organizes policies by:
 * - Resource type (for resource-scoped policies)
 * - Action (for action-scoped policies)
 *
 * This allows O(1) lookup of potentially matching policies instead of
 * scanning all policies for every authorization request.
 *
 * Usage:
 * ```kotlin
 * // Eager initialization at startup
 * val index = PolicyIndex.build(WorkspacePolicies.toSet(), GlobalPolicies.toSet())
 *
 * // Or lazy initialization
 * val index = PolicyIndex.lazy(WorkspacePolicies.toSet(), GlobalPolicies.toSet())
 * ```
 */
class PolicyIndex private constructor(
    private val allPolicies: List<Policy>,
    private val byResource: Map<Resource, List<Policy>>,
    private val globalPolicies: List<Policy>,
    private val forbidPolicies: List<Policy>,
    private val permitPolicies: List<Policy>
) {
    /**
     * Get all policies that might apply to a request.
     * Policies are not ordered; evaluation does not depend on ordering.
     */
    fun getPoliciesFor(resource: Resource?, action: Action?): List<Policy> {
        val candidates = mutableListOf<Policy>()

        // Add global policies (apply to all resources)
        candidates.addAll(globalPolicies)

        // Add resource-specific policies
        if (resource != null) {
            byResource[resource]?.let { candidates.addAll(it) }
        }

        return candidates
    }

    /**
     * Get all forbid policies that might apply to a request.
     * Useful for early-exit optimization (forbid overrides permit).
     */
    fun getForbidPoliciesFor(resource: Resource?): List<Policy> {
        val candidates = mutableListOf<Policy>()

        // Add global forbid policies
        candidates.addAll(forbidPolicies.filter { isGlobalPolicy(it) })

        // Add resource-specific forbid policies
        if (resource != null) {
            candidates.addAll(forbidPolicies.filter {
                matchesResource(it, resource)
            })
        }

        return candidates
    }

    /**
     * Get all permit policies that might apply to a request.
     */
    fun getPermitPoliciesFor(resource: Resource?): List<Policy> {
        val candidates = mutableListOf<Policy>()

        // Add global permit policies
        candidates.addAll(permitPolicies.filter { isGlobalPolicy(it) })

        // Add resource-specific permit policies
        if (resource != null) {
            candidates.addAll(permitPolicies.filter {
                matchesResource(it, resource)
            })
        }

        return candidates
    }

    /**
     * Get all policies in the index.
     */
    fun allPolicies(): List<Policy> = allPolicies

    /**
     * Get statistics about the index.
     */
    fun stats(): IndexStats = IndexStats(
        totalPolicies = allPolicies.size,
        forbidPolicies = forbidPolicies.size,
        permitPolicies = permitPolicies.size,
        globalPolicies = globalPolicies.size,
        resources = byResource.keys.toSet(),
        policiesByResource = byResource.mapValues { it.value.size }
    )

    private fun isGlobalPolicy(policy: Policy): Boolean =
        policy.scope.resource == ResourceScope.Any

    private fun matchesResource(policy: Policy, resource: Resource): Boolean =
        when (val scope = policy.scope.resource) {
            is ResourceScope.Any -> true
            is ResourceScope.OfType -> scope.type == resource
            is ResourceScope.OfTypes -> resource in scope.types
        }

    companion object {
        /**
         * Build the index eagerly (at startup).
         */
        fun build(vararg policySets: PolicySet): PolicyIndex =
            build(policySets.toList())

        /**
         * Build the index eagerly from a list of policy sets.
         */
        fun build(policySets: List<PolicySet>): PolicyIndex {
            val allPolicies = policySets
                .flatMap { it.policies }

            val byResource = mutableMapOf<Resource, MutableList<Policy>>()
            val globalPolicies = mutableListOf<Policy>()

            for (policy in allPolicies) {
                when (val scope = policy.scope.resource) {
                    is ResourceScope.Any -> globalPolicies.add(policy)
                    is ResourceScope.OfType -> {
                        byResource.getOrPut(scope.type) { mutableListOf() }.add(policy)
                    }
                    is ResourceScope.OfTypes -> {
                        for (type in scope.types) {
                            byResource.getOrPut(type) { mutableListOf() }.add(policy)
                    }
                }
                }
            }

            val forbidPolicies = allPolicies.filter { it.effect == PolicyEffect.FORBID }
            val permitPolicies = allPolicies.filter { it.effect == PolicyEffect.PERMIT }

            return PolicyIndex(
                allPolicies = allPolicies,
                byResource = byResource,
                globalPolicies = globalPolicies,
                forbidPolicies = forbidPolicies,
                permitPolicies = permitPolicies
            )
        }

        /**
         * Create a lazy-initialized index.
         * The index is built on first access.
         */
        fun lazy(vararg policySets: PolicySet): Lazy<PolicyIndex> =
            lazy { build(*policySets) }

        /**
         * Create a lazy-initialized index from a list of policy sets.
         */
        fun lazy(policySets: List<PolicySet>): Lazy<PolicyIndex> =
            lazy { build(policySets) }
    }
}

/**
 * Statistics about a PolicyIndex.
 */
data class IndexStats(
    val totalPolicies: Int,
    val forbidPolicies: Int,
    val permitPolicies: Int,
    val globalPolicies: Int,
    val resources: Set<Resource>,
    val policiesByResource: Map<Resource, Int>
)

/**
 * Registry for policy indexes.
 * Allows registering and retrieving indexes by name.
 */
object PolicyIndexRegistry {
    private val indexes = mutableMapOf<String, PolicyIndex>()
    private val lazyIndexes = mutableMapOf<String, Lazy<PolicyIndex>>()

    /**
     * Register an eagerly-built index.
     */
    fun register(name: String, index: PolicyIndex) {
        indexes[name] = index
    }

    /**
     * Register a lazily-built index.
     */
    fun registerLazy(name: String, policySets: List<PolicySet>) {
        lazyIndexes[name] = PolicyIndex.lazy(policySets)
    }

    /**
     * Get an index by name.
     * Returns null if not found.
     */
    fun get(name: String): PolicyIndex? =
        indexes[name] ?: lazyIndexes[name]?.value

    /**
     * Get the default index (named "default").
     */
    fun default(): PolicyIndex? = get("default")

    /**
     * Clear all registered indexes (for testing).
     */
    fun clear() {
        indexes.clear()
        lazyIndexes.clear()
    }
}
