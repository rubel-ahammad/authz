package com.ideascale.commons.authz

/**
 * Principal of authorization.
 *
 * workspaceId: your tenant id boundary
 * memberId: the effective principal (user)
 * actorMemberId: set when impersonating ("admin acting as")
 */
data class Principal(
    val workspaceId: String,
    val memberId: String?,
    val principalType: PrincipalType = PrincipalType.USER,
    val actorMemberId: String? = null
) {
    init {
        require(workspaceId.isNotBlank()) { "workspaceId cannot be blank" }
        require(memberId?.isNotBlank() ?: true) { "memberId cannot be blank if provided" }
        require(actorMemberId?.isNotBlank() ?: true) { "actorMemberId cannot be blank" }
    }

    val isAnonymous: Boolean
        get() = memberId == null

    val isImpersonating: Boolean
        get() = actorMemberId != null && actorMemberId != memberId
}
