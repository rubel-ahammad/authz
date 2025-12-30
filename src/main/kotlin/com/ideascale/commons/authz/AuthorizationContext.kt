package com.ideascale.commons.authz

import com.ideascale.commons.authz.context.*

/**
 * Context for authorization evaluation.
 *
 * Callers build this with whatever context data they have available.
 * All fields are optional - policies gracefully handle missing context
 * (conditions that need missing context evaluate to false).
 *
 * Usage:
 * ```kotlin
 * // Full context
 * val context = AuthorizationContext(
 *     roles = RoleContext(...),
 *     relationships = RelationshipContext(...),
 *     attributes = AttributeContext(...),
 *     resource = IdeaContext(...)
 * )
 *
 * // Partial context (e.g., only roles needed)
 * val context = AuthorizationContext(
 *     roles = RoleContext(...)
 * )
 *
 * // With request metadata
 * val context = AuthorizationContext.builder()
 *     .requestId("req-123")
 *     .roles(roleContext)
 *     .relationships(relationshipContext)
 *     .build()
 * ```
 */
data class AuthorizationContext(
    // Request metadata
    val requestId: String? = null,
    val ip: String? = null,
    val userAgent: String? = null,
    val channel: Channel = Channel.PUBLIC_API,

    // Authorization context (all optional for flexibility)
    val roles: RoleContext? = null,
    val relationships: RelationshipContext? = null,
    val attributes: AttributeContext? = null,
    val resource: ResourceContext? = null
) {
    companion object {
        fun builder() = Builder()
    }

    class Builder {
        private var requestId: String? = null
        private var ip: String? = null
        private var userAgent: String? = null
        private var channel: Channel = Channel.PUBLIC_API
        private var roles: RoleContext? = null
        private var relationships: RelationshipContext? = null
        private var attributes: AttributeContext? = null
        private var resource: ResourceContext? = null

        fun requestId(value: String?) = apply { requestId = value }
        fun ip(value: String?) = apply { ip = value }
        fun userAgent(value: String?) = apply { userAgent = value }
        fun channel(value: Channel) = apply { channel = value }
        fun roles(value: RoleContext?) = apply { roles = value }
        fun relationships(value: RelationshipContext?) = apply { relationships = value }
        fun attributes(value: AttributeContext?) = apply { attributes = value }
        fun resource(value: ResourceContext?) = apply { resource = value }

        fun build() = AuthorizationContext(
            requestId = requestId,
            ip = ip,
            userAgent = userAgent,
            channel = channel,
            roles = roles,
            relationships = relationships,
            attributes = attributes,
            resource = resource
        )
    }
}
