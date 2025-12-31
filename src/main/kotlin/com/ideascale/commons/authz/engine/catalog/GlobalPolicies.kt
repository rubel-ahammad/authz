package com.ideascale.commons.authz.engine.catalog

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.engine.dsl.GlobalPolicySetBase
import com.ideascale.commons.authz.engine.model.Policy

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
     * Cross-tenant access is always denied.
     */
    val tenantMismatchDenyAll: Policy = policy(
        (forbid(
            principal = { any() },
            action = { any() },
            resource = { any() }
        ) `when` {
            resource { tenantMismatch() }
        }).id("global.tenant_mismatch.deny_all")
          .reason(ReasonCode.DENY_TENANT_MISMATCH)
          .priority(1)
          .description("Cross-tenant access is denied")
    )

    /**
     * Resource context must match the requested resource.
     */
    val resourceContextMismatchDenyAll: Policy = policy(
        (forbid(
            principal = { any() },
            action = { any() },
            resource = { any() }
        ) `when` {
            resource { resourceContextMismatch() }
        }).id("global.resource_context_mismatch.deny_all")
          .reason(ReasonCode.DENY_RESOURCE_CONTEXT_MISMATCH)
          .priority(1)
          .description("Resource context must match the requested resource")
    )

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
     * Non-active subscriptions cannot perform any action.
     */
    val inactiveSubscriptionDenyAll: Policy = policy(
        (forbid(
            principal = { any() },
            action = { any() },
            resource = { any() }
        ) `when` {
            attribute {
                subscriptionStateNot(
                    SubscriptionState.ACTIVE,
                    SubscriptionState.SOFT_BLOCKED,
                    SubscriptionState.READ_ONLY
                )
            }
        }).id("global.subscription_inactive.deny_all")
          .reason(ReasonCode.DENY_SUBSCRIPTION_INACTIVE)
          .priority(2)
          .description("Inactive subscription cannot perform any action (excluding soft blocked/read only)")
    )

    /**
     * Soft-blocked subscriptions cannot perform write actions.
     */
    val softBlockedSubscriptionDenyWrite: Policy = policy(
        (forbid(
            principal = { any() },
            action = { oneOf(Action.CREATE, Action.UPDATE, Action.DELETE) },
            resource = { any() }
        ) `when` {
            attribute { subscriptionState(SubscriptionState.SOFT_BLOCKED) }
        }).id("global.subscription_soft_blocked.deny_write")
          .reason(ReasonCode.DENY_SUBSCRIPTION_SOFT_BLOCKED)
          .priority(3)
          .description("Soft-blocked subscription cannot perform write actions")
    )

    /**
     * Read-only subscriptions cannot perform write actions.
     */
    val readOnlySubscriptionDenyWrite: Policy = policy(
        (forbid(
            principal = { any() },
            action = { oneOf(Action.CREATE, Action.UPDATE, Action.DELETE) },
            resource = { any() }
        ) `when` {
            attribute { subscriptionState(SubscriptionState.READ_ONLY) }
        }).id("global.subscription_read_only.deny_write")
          .reason(ReasonCode.DENY_SUBSCRIPTION_READ_ONLY)
          .priority(4)
          .description("Read-only subscription cannot perform write actions")
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
            action = { oneOf(Action.CREATE, Action.UPDATE, Action.DELETE) },
            resource = { any() }
        ) `when` {
            attribute { workspaceReadOnly() }
        }).id("global.workspace_readonly.deny_write")
          .reason(ReasonCode.DENY_WORKSPACE_READONLY)
          .priority(5)
          .description("Workspace in read-only mode denies write operations")
    )
}
