package com.ideascale.commons.authz.context

import com.ideascale.commons.authz.Channel
import java.time.Instant
import java.util.UUID

/**
 * Environment context for an authorization request.
 *
 * Captures metadata about the request environment - not about WHO (Principal)
 * or WHAT (Resource), but WHEN/WHERE/HOW the request was made.
 *
 * Used for:
 * - IP-based restrictions
 * - Channel-specific policies (stricter admin routes)
 * - Time-based policies
 * - Audit logging
 */
data class EnvironmentContext(
    val requestId: String = UUID.randomUUID().toString(),
    val ip: String? = null,
    val channel: Channel = Channel.PUBLIC_API,
    val userAgent: String? = null,
    val timestamp: Instant = Instant.now()
) {
    companion object {
        /**
         * Default environment for internal service calls.
         */
        val INTERNAL = EnvironmentContext(channel = Channel.INTERNAL_SERVICE)

        /**
         * Default environment for background jobs.
         */
        val JOB = EnvironmentContext(channel = Channel.INTERNAL_JOB)
    }
}
