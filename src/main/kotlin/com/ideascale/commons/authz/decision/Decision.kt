package com.ideascale.commons.authz.decision

import java.util.UUID

/**
 * Authorization decision.
 *
 * decisionId: lets you correlate logs across microservices.
 * details: optional structured info (e.g., matchedRuleId, matchedGrant, policyVersion).
 */
data class Decision(
    val effect: Effect,
    val reason: ReasonCode,
    val obligations: Set<Obligation> = emptySet(),
    val decisionId: String = UUID.randomUUID().toString(),
    val details: Map<String, String> = emptyMap()
) {
    val allowed: Boolean get() = effect == Effect.ALLOW

    companion object {
        fun allow(
            reason: ReasonCode = ReasonCode.ALLOW_SYSTEM,
            obligations: Set<Obligation> = emptySet(),
            details: Map<String, String> = emptyMap()
        ): Decision = Decision(
            effect = Effect.ALLOW,
            reason = reason,
            obligations = obligations,
            details = details
        )

        fun deny(
            reason: ReasonCode = ReasonCode.DENY_DEFAULT,
            details: Map<String, String> = emptyMap()
        ): Decision = Decision(
            effect = Effect.DENY,
            reason = reason,
            details = details
        )
    }
}
