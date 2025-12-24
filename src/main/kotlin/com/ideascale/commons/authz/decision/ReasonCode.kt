package com.ideascale.commons.authz.decision

/**
 * Stable reason codes for audit/debug/support.
 *
 * Governance rules:
 * - NEVER rename existing codes (treat as API)
 * - Add new codes as needed
 * - Codes are UPPER_SNAKE_CASE
 * - Prefix with ALLOW_ or DENY_
 */
@JvmInline
value class ReasonCode(val value: String) {
    init {
        require(value.isNotBlank()) { "ReasonCode cannot be blank" }
    }

    override fun toString(): String = value

    companion object {
        // Generic / framework-level
        val DENY_DEFAULT = ReasonCode("DENY_DEFAULT")
        val DENY_NOT_AUTHENTICATED = ReasonCode("DENY_NOT_AUTHENTICATED")
        val DENY_TENANT_MISMATCH = ReasonCode("DENY_TENANT_MISMATCH")

        // Hard gates (ABAC-style global denies)
        val DENY_BANNED = ReasonCode("DENY_BANNED")
        val DENY_PENDING = ReasonCode("DENY_PENDING")
        val DENY_SUBSCRIPTION_BLOCKED = ReasonCode("DENY_SUBSCRIPTION_BLOCKED")
        val DENY_IP_RESTRICTED = ReasonCode("DENY_IP_RESTRICTED")
        val DENY_EMAIL_DOMAIN_BLOCKED = ReasonCode("DENY_EMAIL_DOMAIN_BLOCKED")
        val DENY_EMAIL_DOMAIN_NOT_ALLOWED = ReasonCode("DENY_EMAIL_DOMAIN_NOT_ALLOWED")

        // Scope/relationship
        val DENY_NOT_IN_SCOPE = ReasonCode("DENY_NOT_IN_SCOPE")
        val DENY_INSUFFICIENT_PRIVILEGE = ReasonCode("DENY_INSUFFICIENT_PRIVILEGE")

        // Resource state
        val DENY_WORKSPACE_READONLY = ReasonCode("DENY_WORKSPACE_READONLY")
        val DENY_WORKSPACE_PRIVATE = ReasonCode("DENY_WORKSPACE_PRIVATE")
        val DENY_RESOURCE_READONLY = ReasonCode("DENY_RESOURCE_READONLY")
        val DENY_CAMPAIGN_EXPIRED = ReasonCode("DENY_CAMPAIGN_EXPIRED")
        val DENY_IDEA_LOCKED = ReasonCode("DENY_IDEA_LOCKED")
        val DENY_IDEA_ARCHIVED = ReasonCode("DENY_IDEA_ARCHIVED")

        // Allows (generic)
        val ALLOW_ROLE = ReasonCode("ALLOW_ROLE")
        val ALLOW_OWNER = ReasonCode("ALLOW_OWNER")
        val ALLOW_RELATIONSHIP = ReasonCode("ALLOW_RELATIONSHIP")
        val ALLOW_SYSTEM = ReasonCode("ALLOW_SYSTEM")
    }
}
