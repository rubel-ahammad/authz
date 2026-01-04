package com.ideascale.commons.authz

import com.ideascale.commons.authz.context.EnvironmentContext
import com.ideascale.commons.authz.context.PrincipalContext
import com.ideascale.commons.authz.context.ResourceContext

/**
 * Complete context for an authorization decision.
 *
 * Combines:
 * - **PrincipalContext**: WHO (roles + member attributes) - Cedar Membership Pattern
 * - **ResourceContext**: WHAT (resource + relationships + attributes) - Cedar Relationship Pattern
 * - **EnvironmentContext**: WHERE/WHEN/HOW (request metadata)
 *
 * Usage:
 * ```kotlin
 * val context = AuthorizationContext(
 *     principal = PrincipalContext(
 *         status = MemberStatus.ACTIVE,
 *         workspaceRole = WorkspaceRole.MEMBER,
 *         campaignModerator = setOf(456L)
 *     ),
 *     resource = IdeaContext(
 *         id = 789L,
 *         workspace = WorkspaceAttributes(id = 1L),
 *         community = CommunityAttributes(id = 10L),
 *         campaign = CampaignAttributes(id = 456L),
 *         state = IdeaState.ACTIVE,
 *         owner = 123L
 *     ),
 *     environment = EnvironmentContext(ip = "192.168.1.1")
 * )
 *
 * // Policy checks:
 * context.principal.isCampaignModerator(456L)
 * (context.resource as IdeaContext).isOwner(123L)
 * context.resource.workspace.subscriptionState == SubscriptionState.ACTIVE
 * ```
 */
data class AuthorizationContext(
    /**
     * Principal's roles and attributes (Membership Pattern + ABAC).
     */
    val principal: PrincipalContext,

    /**
     * Resource being accessed with its relationships and attributes (Relationship Pattern + ABAC).
     * Null when checking workspace-level permissions without a specific resource.
     */
    val resource: ResourceContext? = null,

    /**
     * Request environment metadata.
     */
    val environment: EnvironmentContext = EnvironmentContext()
) {
    companion object {
        /**
         * Create a builder for AuthorizationContext.
         */
        fun builder() = Builder()

        /**
         * Create context for anonymous access.
         */
        fun anonymous(resource: ResourceContext? = null, environment: EnvironmentContext = EnvironmentContext()) =
            AuthorizationContext(
                principal = PrincipalContext.ANONYMOUS,
                resource = resource,
                environment = environment
            )
    }

    class Builder {
        private var principal: PrincipalContext = PrincipalContext.ANONYMOUS
        private var resource: ResourceContext? = null
        private var environment: EnvironmentContext = EnvironmentContext()

        fun principal(value: PrincipalContext) = apply { principal = value }
        fun resource(value: ResourceContext?) = apply { resource = value }
        fun environment(value: EnvironmentContext) = apply { environment = value }

        // Convenience setters for environment
        fun ip(value: String?) = apply {
            environment = environment.copy(ip = value)
        }

        fun channel(value: Channel) = apply {
            environment = environment.copy(channel = value)
        }

        fun requestId(value: String) = apply {
            environment = environment.copy(requestId = value)
        }

        fun build() = AuthorizationContext(
            principal = principal,
            resource = resource,
            environment = environment
        )
    }
}
