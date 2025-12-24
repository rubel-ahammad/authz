package com.ideascale.commons.authz

/**
 * Purpose-built context. Keep it typed and stable.
 *
 * attributes: reserved escape hatch for non-core signals; keep it small and documented.
 */
data class AuthzContext(
    val requestId: String? = null,
    val ip: String? = null,
    val userAgent: String? = null,
    val channel: Channel = Channel.PUBLIC_API,
    val attributes: Map<String, String> = emptyMap()
)
