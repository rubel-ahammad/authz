package com.ideascale.commons.authz.context

@JvmInline
value class RoleId(val value: String) {
    init {
        require(value.isNotBlank()) { "RoleId cannot be blank" }
    }

    override fun toString(): String = value
}

data class RoleContext(
    val workspaceRoles: Set<RoleId> = emptySet(),
    val communityRoles: Set<RoleId> = emptySet(),
    val campaignRoles: Set<RoleId> = emptySet(),
    val groupRoles: Set<RoleId> = emptySet()
)
