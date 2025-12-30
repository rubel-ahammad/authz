package com.ideascale.commons.authz

import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.engine.PolicyEngineAuthorizer
import com.ideascale.commons.authz.engine.catalog.GlobalPolicies
import com.ideascale.commons.authz.engine.catalog.IdeaActionsHierarchy
import com.ideascale.commons.authz.engine.catalog.IdeaPolicies
import com.ideascale.commons.authz.resource.Resource
import com.ideascale.commons.authz.resource.ResourceType
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SubscriptionPoliciesTest {

    private val workspaceId = "w-1"
    private val communityId = "c-1"
    private val campaignId = "ca-1"
    private val ideaId = "i-1"

    private val authorizer = PolicyEngineAuthorizer(
        GlobalPolicies.toSet(),
        IdeaPolicies.toSet()
    )

    private fun principal(): Principal = Principal(
        workspaceId = workspaceId,
        memberId = "m-1"
    )

    private fun resource(): Resource = Resource(
        type = ResourceType.IDEA,
        id = ideaId
    )

    private fun context(state: SubscriptionState): AuthorizationContext =
        AuthorizationContext(
            roles = RoleContext(workspaceRoles = setOf(RoleIds.WORKSPACE_ADMIN)),
            resource = IdeaContext(workspaceId, communityId, campaignId, ideaId),
            attributes = AttributeContext(
                workspace = WorkspaceAttrs(
                    subscription = SubscriptionAttrs(state),
                    network = NetworkAttrs(IpRestrictionResult.Allowed),
                    emailDomain = EmailDomainAttrs(),
                    flags = WorkspaceFlags(isPublic = true, isReadOnlyMode = false)
                ),
                member = MemberAttrs(MemberStatus.MEMBER),
                request = RequestAttrs(ip = "203.0.113.1", channel = Channel.PUBLIC_API),
                campaign = CampaignAttrs(state = CampaignState.LAUNCHED),
                idea = IdeaAttrs(state = IdeaState.ACTIVE)
            )
        )

    @Test
    fun `active subscription allows read and write`() {
        val decisionRead = authorizer.authorize(
            principal(),
            IdeaActionsHierarchy.view,
            resource(),
            context(SubscriptionState.ACTIVE)
        )
        assertTrue(decisionRead.allowed)

        val decisionWrite = authorizer.authorize(
            principal(),
            IdeaActionsHierarchy.edit,
            resource(),
            context(SubscriptionState.ACTIVE)
        )
        assertTrue(decisionWrite.allowed)
    }

    @Test
    fun `blocked subscription denies read and write`() {
        val decisionRead = authorizer.authorize(
            principal(),
            IdeaActionsHierarchy.view,
            resource(),
            context(SubscriptionState.BLOCKED)
        )
        assertFalse(decisionRead.allowed)
        assertEquals(ReasonCode.DENY_SUBSCRIPTION_BLOCKED, decisionRead.reason)

        val decisionWrite = authorizer.authorize(
            principal(),
            IdeaActionsHierarchy.edit,
            resource(),
            context(SubscriptionState.BLOCKED)
        )
        assertFalse(decisionWrite.allowed)
        assertEquals(ReasonCode.DENY_SUBSCRIPTION_BLOCKED, decisionWrite.reason)
    }

    @Test
    fun `soft blocked subscription denies write but allows read`() {
        val decisionRead = authorizer.authorize(
            principal(),
            IdeaActionsHierarchy.view,
            resource(),
            context(SubscriptionState.SOFT_BLOCKED)
        )
        assertTrue(decisionRead.allowed)

        val decisionWrite = authorizer.authorize(
            principal(),
            IdeaActionsHierarchy.edit,
            resource(),
            context(SubscriptionState.SOFT_BLOCKED)
        )
        assertFalse(decisionWrite.allowed)
        assertEquals(ReasonCode.DENY_SUBSCRIPTION_SOFT_BLOCKED, decisionWrite.reason)
    }

    @Test
    fun `read only subscription denies write but allows read`() {
        val decisionRead = authorizer.authorize(
            principal(),
            IdeaActionsHierarchy.view,
            resource(),
            context(SubscriptionState.READ_ONLY)
        )
        assertTrue(decisionRead.allowed)

        val decisionWrite = authorizer.authorize(
            principal(),
            IdeaActionsHierarchy.edit,
            resource(),
            context(SubscriptionState.READ_ONLY)
        )
        assertFalse(decisionWrite.allowed)
        assertEquals(ReasonCode.DENY_SUBSCRIPTION_READ_ONLY, decisionWrite.reason)
    }
}
