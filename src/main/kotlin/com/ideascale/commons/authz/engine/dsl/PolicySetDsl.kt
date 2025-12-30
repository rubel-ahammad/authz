package com.ideascale.commons.authz.engine.dsl

import com.ideascale.commons.authz.engine.model.Policy
import com.ideascale.commons.authz.engine.model.PolicyEffect
import com.ideascale.commons.authz.engine.model.PolicySet
import com.ideascale.commons.authz.resource.ResourceType

/**
 * Base class for defining a set of policies for a resource type.
 *
 * Usage:
 * ```kotlin
 * object WorkspacePolicies : PolicySetBase(ResourceType.WORKSPACE) {
 *
 *     val adminFullAccess = policy(
 *         permit(
 *             principal = { hasRole(RoleIds.WORKSPACE_ADMIN) },
 *             action = { `in`(WorkspaceActionsHierarchy) },
 *             resource = { any() }
 *         )
 *         .id("idea.admin.full_access")
 *         .reason(ReasonCode.ALLOW_ROLE)
 *     )
 *
 *     val ownerCanEdit = policy(
 *         permit(
 *             principal = { authenticated() },
 *             action = { eq(WorkspaceActionsHierarchy.update) },
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
 * @param resourceType Optional resource type this policy set applies to
 */
abstract class PolicySetBase(
    protected val resourceType: ResourceType? = null
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
     * Create a permit policy with default resource scope based on resourceType.
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
     * Create a forbid policy with default resource scope based on resourceType.
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
        if (resourceType != null) {
            ofType(resourceType)
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
        resourceType = resourceType,
        policies = policies(),
        description = "Policies for ${resourceType?.name ?: "global"}"
    )
}

/**
 * Base class for global policies that apply across all resource types.
 */
abstract class GlobalPolicySetBase : PolicySetBase(null)
