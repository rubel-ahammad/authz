package com.ideascale.commons.authz.engine

import com.ideascale.commons.authz.core.Authorizer
import com.ideascale.commons.authz.core.ReasonCode
import com.ideascale.commons.authz.core.ResourceRef
import com.ideascale.commons.authz.core.ResourceType
import com.ideascale.commons.authz.core.action.WorkspaceActions
import com.ideascale.commons.authz.fixture.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertEquals

class WorkspaceAuthorizationTest {

    private val workspaceId = TestSubjects.WORKSPACE_ID
    private val workspaceResource = ResourceRef(ResourceType.WORKSPACE, workspaceId)

    @Test
    fun `anonymous user can read workspace`() {
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder().build()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.anonymous,
            action = WorkspaceActions.READ,
            resource = workspaceResource
        )

        assertTrue(decision.allowed, "Anonymous user should be able to read workspace")
        assertEquals(ReasonCode.ALLOW_ROLE, decision.reason)
    }

    @Test
    fun `anonymous user cannot read private workspace`() {
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder().build(),
            attributeProvider = TestAttributeContextProvider.privateWorkspace()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.anonymous,
            action = WorkspaceActions.READ,
            resource = workspaceResource
        )

        assertFalse(decision.allowed, "Anonymous user should not be able to read private workspace")
        assertEquals(ReasonCode.DENY_WORKSPACE_PRIVATE, decision.reason)
    }

    @Test
    fun `anonymous user cannot write workspace`() {
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder().build()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.anonymous,
            action = WorkspaceActions.UPDATE,
            resource = workspaceResource
        )

        assertFalse(decision.allowed, "Anonymous user should not be able to write workspace")
        assertEquals(ReasonCode.DENY_DEFAULT, decision.reason)
    }

    @Test
    fun `workspace member can read workspace`() {
        val memberId = TestSubjects.workspaceMember.memberId!!
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder()
                .withWorkspaceMember(memberId)
                .build()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.workspaceMember,
            action = WorkspaceActions.READ,
            resource = workspaceResource
        )

        assertTrue(decision.allowed, "Workspace member should be able to read workspace")
        assertEquals(ReasonCode.ALLOW_ROLE, decision.reason)
    }

    @Test
    fun `workspace member cannot write workspace`() {
        val memberId = TestSubjects.workspaceMember.memberId!!
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder()
                .withWorkspaceMember(memberId)
                .build()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.workspaceMember,
            action = WorkspaceActions.UPDATE,
            resource = workspaceResource
        )

        assertFalse(decision.allowed, "Workspace member should not be able to write workspace")
        assertEquals(ReasonCode.DENY_DEFAULT, decision.reason)
    }

    @Test
    fun `workspace admin can write workspace`() {
        val adminId = TestSubjects.workspaceAdmin.memberId!!
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder()
                .withWorkspaceAdmin(adminId)
                .build()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.workspaceAdmin,
            action = WorkspaceActions.UPDATE,
            resource = workspaceResource
        )

        assertTrue(decision.allowed, "Workspace admin should be able to write workspace")
        assertEquals(ReasonCode.ALLOW_ROLE, decision.reason)
    }

    private fun buildAuthorizer(
        roleProvider: TestRoleContextProvider = TestRoleContextProvider.builder().build(),
        relationshipProvider: TestRelationshipContextProvider = TestRelationshipContextProvider.default(),
        attributeProvider: TestAttributeContextProvider = TestAttributeContextProvider.activeWorkspace(),
        resourceProvider: TestResourceContextProvider = TestResourceContextProvider.forWorkspace()
    ): Authorizer {
        return PipelineAuthorizerFactory.build(
            PipelineDependencies(
                resourceContextProvider = resourceProvider,
                relationshipContextProvider = relationshipProvider,
                attributeContextProvider = attributeProvider,
                roleContextProvider = roleProvider
            )
        )
    }
}
