package com.ideascale.commons.authz.core

/**
 * Subject of authorization.
 *
 * workspaceId: your tenant id boundary
 * memberId: the effective subject (user)
 * actorMemberId: set when impersonating ("admin acting as")
 */
data class Subject(
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
