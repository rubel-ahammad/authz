package com.ideascale.commons.authz.engine.model

import com.ideascale.commons.authz.resource.ResourceType

/**
 * A collection of policies, typically grouped by resource type.
 *
 * Policy sets provide organization and can be composed to form a complete
 * authorization policy catalog.
 *
 * @param id Unique identifier for the policy set
 * @param resourceType Optional resource type this set applies to (null for global policies)
 * @param policies List of policies in this set
 * @param description Human-readable description
 */
data class PolicySet(
    val id: String,
    val resourceType: ResourceType? = null,
    val policies: List<Policy>,
    val description: String? = null
) {
    /**
     * All PERMIT policies in this set.
     */
    val permitPolicies: List<Policy> by lazy {
        policies.filter { it.effect == PolicyEffect.PERMIT }
    }

    /**
     * All FORBID policies in this set.
     */
    val forbidPolicies: List<Policy> by lazy {
        policies.filter { it.effect == PolicyEffect.FORBID }
    }

    /**
     * Policies sorted by priority (lower number = higher priority).
     */
    val sortedPolicies: List<Policy> by lazy {
        policies.sortedBy { it.priority }
    }

    companion object {
        /**
         * Create a policy set from multiple policy sets.
         */
        fun merge(id: String, vararg sets: PolicySet): PolicySet = PolicySet(
            id = id,
            resourceType = null,
            policies = sets.flatMap { it.policies },
            description = "Merged policy set from: ${sets.map { it.id }.joinToString(", ")}"
        )
    }
}
