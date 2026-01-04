package com.ideascale.commons.authz

/**
 * Principal of authorization - represents WHO is making the request.
 *
 * @property id Member ID (null for anonymous users)
 * @property type Type of principal (USER, SERVICE)
 * @property workspaceId Tenant boundary
 * @property actorId For impersonation: the actual admin performing actions on behalf of another user
 *
 * Anonymous users are represented as type USER with id = null.
 */
data class Principal(
    val id: Long?,
    val type: PrincipalType,
    val workspaceId: Long,
    val actorId: Long? = null
) {
    init {
        require(workspaceId > 0) { "workspaceId must be positive" }
        require(id == null || id > 0) { "id must be positive if provided" }
        require(actorId == null || actorId > 0) { "actorId must be positive if provided" }
        if (type == PrincipalType.SERVICE) {
            require(id != null) { "service principals must have an id" }
        }
    }

    /**
     * True if this is an anonymous (unauthenticated) principal.
     */
    val isAnonymous: Boolean
        get() = id == null

    /**
     * True if this is an authenticated principal (user or service).
     */
    val isAuthenticated: Boolean
        get() = !isAnonymous

    /**
     * True if an admin is acting on behalf of another user.
     */
    val isImpersonating: Boolean
        get() = actorId != null && actorId != id

    companion object {
        /**
         * Create a user principal.
         */
        fun user(id: Long, workspaceId: Long) = Principal(
            id = id,
            type = PrincipalType.USER,
            workspaceId = workspaceId
        )

        /**
         * Create a service principal.
         */
        fun service(id: Long, workspaceId: Long) = Principal(
            id = id,
            type = PrincipalType.SERVICE,
            workspaceId = workspaceId
        )

        /**
         * Create an anonymous principal.
         */
        fun anonymous(workspaceId: Long) = Principal(
            id = null,
            type = PrincipalType.USER,
            workspaceId = workspaceId
        )

        /**
         * Create a principal for impersonation (admin acting as another user).
         *
         * @param effectiveId The user being acted as
         * @param actorId The admin performing the action
         * @param workspaceId Tenant boundary
         */
        fun impersonating(effectiveId: Long, actorId: Long, workspaceId: Long) = Principal(
            id = effectiveId,
            type = PrincipalType.USER,
            workspaceId = workspaceId,
            actorId = actorId
        )
    }
}
