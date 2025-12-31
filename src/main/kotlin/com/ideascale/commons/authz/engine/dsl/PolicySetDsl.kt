package com.ideascale.commons.authz.engine.dsl

import com.ideascale.commons.authz.engine.model.Policy
import com.ideascale.commons.authz.engine.model.PolicyEffect
import com.ideascale.commons.authz.engine.model.PolicySet
import com.ideascale.commons.authz.resource.Resource

/**
 * Base class for defining a set of policies for a resource type.
 *
 * Usage:
 * ```kotlin
 * object WorkspacePolicies : PolicySetBase(Resource.WORKSPACE) {
 *
 *     val adminFullAccess = policy(
 *         permit(
 *             principal = { hasRole(Role.WORKSPACE_ADMIN) },
 *             action = { any() },
 *             resource = { any() }
 *         )
 *         .id("idea.admin.full_access")
 *         .reason(ReasonCode.ALLOW_ROLE)
 *     )
 *
 *     val ownerCanEdit = policy(
 *         permit(
 *             principal = { authenticated() },
 *             action = { eq(Action.UPDATE) },
 *             resource = { any() }
 *         ) `when` {
 *             relationship { isOwner() }
 *         }
 *         .id("idea.owner.edit")
 *         .reason(ReasonCode.ALLOW_OWNER)
 *     )
 * }
 * ```
 *
 * @param resource Optional resource this policy set applies to
 */
abstract class PolicySetBase(
    protected val resource: Resource? = null
) {
    private val _policies = mutableSetOf<Policy>()

    /**
     * Register a policy and return it.
     */
    protected fun policy(builder: PolicyBuilder): Policy {
        val policy = builder.build()
        _policies.add(policy)
        return policy
    }

    /**
     * Create a permit policy with default resource scope based on resource.
     */
    protected fun permit(
        principal: PrincipalScopeBuilder.() -> Unit = { any() },
        action: ActionScopeBuilder.() -> Unit = { any() },
        resource: ResourceScopeBuilder.() -> Unit = defaultResourceScope()
    ): PolicyBuilder = PolicyBuilder(PolicyEffect.PERMIT).apply {
        this.principal(principal)
        this.action(action)
        this.resource(resource)
    }

    /**
     * Create a forbid policy with default resource scope based on resource.
     */
    protected fun forbid(
        principal: PrincipalScopeBuilder.() -> Unit = { any() },
        action: ActionScopeBuilder.() -> Unit = { any() },
        resource: ResourceScopeBuilder.() -> Unit = defaultResourceScope()
    ): PolicyBuilder = PolicyBuilder(PolicyEffect.FORBID).apply {
        this.principal(principal)
        this.action(action)
        this.resource(resource)
    }

    private fun defaultResourceScope(): ResourceScopeBuilder.() -> Unit = {
        if (resource != null) {
            ofType(resource)
        } else {
            any()
        }
    }

    /**
     * Get all registered policies.
     */
    fun policies(): Set<Policy> = _policies.toSet()

    /**
     * Build the PolicySet.
     */
    fun toSet(): PolicySet = PolicySet(
        id = this::class.simpleName ?: "anonymous",
        resource = resource,
        policies = policies(),
        description = "Policies for ${resource?.name ?: "global"}"
    )
}

/**
 * Base class for global policies that apply across all resource types.
 */
abstract class GlobalPolicySetBase : PolicySetBase(null)
