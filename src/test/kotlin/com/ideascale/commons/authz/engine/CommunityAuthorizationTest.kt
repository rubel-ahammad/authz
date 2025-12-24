package com.ideascale.commons.authz.engine

import com.ideascale.commons.authz.core.Authorizer
import com.ideascale.commons.authz.core.ReasonCode
import com.ideascale.commons.authz.core.ResourceRef
import com.ideascale.commons.authz.core.ResourceType
import com.ideascale.commons.authz.core.action.CommunityActions
import com.ideascale.commons.authz.fixture.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertEquals

class CommunityAuthorizationTest {

    private val communityId = "community-1"
    private val communityResource = ResourceRef(ResourceType.COMMUNITY, communityId)

    @Test
    fun `anonymous user can read community`() {
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder().build()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.anonymous,
            action = CommunityActions.READ,
            resource = communityResource
        )

        assertTrue(decision.allowed, "Anonymous user should be able to read community")
        assertEquals(ReasonCode.ALLOW_ROLE, decision.reason)
    }

    @Test
    fun `anonymous user cannot update community`() {
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder().build()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.anonymous,
            action = CommunityActions.UPDATE,
            resource = communityResource
        )

        assertFalse(decision.allowed, "Anonymous user should not be able to update community")
        assertEquals(ReasonCode.DENY_DEFAULT, decision.reason)
    }

    @Test
    fun `community member can read community`() {
        val memberId = TestSubjects.workspaceMember.memberId!!
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder()
                .withCommunityMember(communityId, memberId)
                .build()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.workspaceMember,
            action = CommunityActions.READ,
            resource = communityResource
        )

        assertTrue(decision.allowed, "Community member should be able to read community")
        assertEquals(ReasonCode.ALLOW_ROLE, decision.reason)
    }

    @Test
    fun `community member cannot update community`() {
        val memberId = TestSubjects.workspaceMember.memberId!!
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder()
                .withCommunityMember(communityId, memberId)
                .build()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.workspaceMember,
            action = CommunityActions.UPDATE,
            resource = communityResource
        )

        assertFalse(decision.allowed, "Community member should not be able to update community")
        assertEquals(ReasonCode.DENY_DEFAULT, decision.reason)
    }

    @Test
    fun `community admin can update community`() {
        val adminId = TestSubjects.workspaceAdmin.memberId!!
        val authorizer = buildAuthorizer(
            roleProvider = TestRoleContextProvider.builder()
                .withCommunityAdmin(communityId, adminId)
                .build()
        )

        val decision = authorizer.authorize(
            subject = TestSubjects.workspaceAdmin,
            action = CommunityActions.UPDATE,
            resource = communityResource
        )

        assertTrue(decision.allowed, "Community admin should be able to update community")
        assertEquals(ReasonCode.ALLOW_ROLE, decision.reason)
    }

    private fun buildAuthorizer(
        roleProvider: TestRoleContextProvider = TestRoleContextProvider.builder().build(),
        relationshipProvider: TestRelationshipContextProvider = TestRelationshipContextProvider.default(),
        attributeProvider: TestAttributeContextProvider = TestAttributeContextProvider.activeWorkspace(),
        resourceProvider: TestResourceContextProvider = TestResourceContextProvider.forCommunity(communityId)
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
