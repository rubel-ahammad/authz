package com.ideascale.commons.authz.engine.catalog

import com.ideascale.commons.authz.engine.dsl.GlobalPolicySetBase
import com.ideascale.commons.authz.engine.model.Policy
import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.decision.ReasonCode

/**
 * Global policies that apply across all resource types.
 *
 * These are typically "hard gates" that must be checked before
 * any resource-specific policies.
 */
object GlobalPolicies : GlobalPolicySetBase() {

    // ========================================================================
    // FORBID POLICIES - Hard Gates
    // ========================================================================

    /**
     * Banned members cannot perform any action.
     */
    val bannedMemberDenyAll: Policy = policy(
        (forbid(
            principal = { any() },
            action = { any() },
            resource = { any() }
        ) `when` {
            attribute { memberStatus(MemberStatus.BANNED) }
        }).id("global.banned.deny_all")
          .reason(ReasonCode.DENY_BANNED)
          .priority(1)
          .description("Banned members cannot perform any action")
    )

    /**
     * Blocked subscription cannot perform any action.
     */
    val blockedSubscriptionDenyAll: Policy = policy(
        (forbid(
            principal = { any() },
            action = { any() },
            resource = { any() }
        ) `when` {
            attribute { subscriptionState(SubscriptionState.BLOCKED) }
        }).id("global.subscription_blocked.deny_all")
          .reason(ReasonCode.DENY_SUBSCRIPTION_BLOCKED)
          .priority(1)
          .description("Blocked subscription cannot perform any action")
    )

    /**
     * IP restricted requests are denied.
     */
    val ipRestrictedDenyAll: Policy = policy(
        (forbid(
            principal = { any() },
            action = { any() },
            resource = { any() }
        ) `when` {
            attribute { ipRestricted() }
        }).id("global.ip_restricted.deny_all")
          .reason(ReasonCode.DENY_IP_RESTRICTED)
          .priority(1)
          .description("IP restricted requests are denied")
    )

    /**
     * Workspace in read-only mode - deny all write operations.
     * Note: This is a broad deny; specific actions would need to be defined.
     */
    val workspaceReadOnlyDenyWrite: Policy = policy(
        (forbid(
            principal = { any() },
            action = { any() },
            resource = { any() }
        ) `when` {
            attribute { workspaceReadOnly() }
        }).id("global.workspace_readonly.deny_write")
          .reason(ReasonCode.DENY_WORKSPACE_READONLY)
          .priority(5)
          .description("Workspace in read-only mode denies write operations")
    )
}
