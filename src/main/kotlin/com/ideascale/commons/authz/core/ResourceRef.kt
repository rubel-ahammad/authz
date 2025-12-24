package com.ideascale.commons.authz.core

/**
 * Reference to a protected resource.
 *
 * id: Use your canonical identifier for the resource (stringified UUID/Long/etc).
 * workspaceId is carried in Subject (tenant boundary), not duplicated here.
 */
data class ResourceRef(
    val type: ResourceType,
    val id: String
) {
    init {
        require(id.isNotBlank()) { "Resource id cannot be blank" }
    }
}
