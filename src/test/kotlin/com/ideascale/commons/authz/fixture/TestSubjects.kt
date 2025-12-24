package com.ideascale.commons.authz.fixture

import com.ideascale.commons.authz.core.Subject

object TestSubjects {
    const val WORKSPACE_ID = "test-workspace-1"

    val anonymous = Subject(
        workspaceId = WORKSPACE_ID,
        memberId = null
    )

    val workspaceMember = Subject(
        workspaceId = WORKSPACE_ID,
        memberId = "member-1"
    )

    val workspaceAdmin = Subject(
        workspaceId = WORKSPACE_ID,
        memberId = "admin-1"
    )
}
