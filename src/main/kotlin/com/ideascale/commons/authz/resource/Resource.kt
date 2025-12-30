package com.ideascale.commons.authz.resource

/**
 * Reference to a protected resource.
 *
 * id: Use your canonical identifier for the resource (stringified UUID/Long/etc).
 * workspaceId is carried in Principal (tenant boundary), not duplicated here.
 */
data class Resource(
    val type: ResourceType,
    val id: String
) {
    init {
        require(id.isNotBlank()) { "Resource id cannot be blank" }
    }
}
