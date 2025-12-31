package com.ideascale.commons.authz

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.engine.PolicyEngineAuthorizer
import com.ideascale.commons.authz.engine.catalog.GlobalPolicies
import com.ideascale.commons.authz.engine.dsl.PolicySetBase
import com.ideascale.commons.authz.engine.model.Policy
import com.ideascale.commons.authz.resource.Resource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private object TestWorkspacePolicies : PolicySetBase(Resource.WORKSPACE) {
    val allowAll: Policy = policy(
        permit(
            principal = { any() },
            action = { any() },
            resource = { ofType(Resource.WORKSPACE) }
        ).id("test.workspace.allow_all")
         .reason(ReasonCode.ALLOW_SYSTEM)
    )
}

class SubscriptionPoliciesTest {

    private val workspaceId = "w-1"

    private val authorizer = PolicyEngineAuthorizer(
        GlobalPolicies.toSet(),
        TestWorkspacePolicies.toSet()
    )

    private fun principal(): Principal = Principal(
        workspaceId = workspaceId,
        memberId = "m-1"
    )

    private fun context(state: SubscriptionState): AuthorizationContext =
        AuthorizationContext(
            resource = WorkspaceContext(workspaceId),
            attributes = AttributeContext(
                workspace = WorkspaceAttrs(
                    subscription = SubscriptionAttrs(state),
                    network = NetworkAttrs(IpRestrictionResult.Allowed),
                    emailDomain = EmailDomainAttrs(),
                    flags = WorkspaceFlags(isPublic = true, isReadOnlyMode = false)
                ),
                member = MemberAttrs(MemberStatus.MEMBER),
                request = RequestAttrs(ip = "203.0.113.1", channel = Channel.PUBLIC_API)
            )
        )

    @Test
    fun `active subscription allows read and write`() {
        val decisionRead = authorizer.authorize(
            principal(),
            Action.READ,
            Resource.WORKSPACE,
            context(SubscriptionState.ACTIVE)
        )
        assertTrue(decisionRead.allowed)

        val decisionWrite = authorizer.authorize(
            principal(),
            Action.UPDATE,
            Resource.WORKSPACE,
            context(SubscriptionState.ACTIVE)
        )
        assertTrue(decisionWrite.allowed)
    }

    @Test
    fun `blocked subscription denies read and write`() {
        val decisionRead = authorizer.authorize(
            principal(),
            Action.READ,
            Resource.WORKSPACE,
            context(SubscriptionState.BLOCKED)
        )
        assertFalse(decisionRead.allowed)
        assertEquals(ReasonCode.DENY_SUBSCRIPTION_BLOCKED, decisionRead.reason)

        val decisionWrite = authorizer.authorize(
            principal(),
            Action.UPDATE,
            Resource.WORKSPACE,
            context(SubscriptionState.BLOCKED)
        )
        assertFalse(decisionWrite.allowed)
        assertEquals(ReasonCode.DENY_SUBSCRIPTION_BLOCKED, decisionWrite.reason)
    }

    @Test
    fun `soft blocked subscription denies write but allows read`() {
        val decisionRead = authorizer.authorize(
            principal(),
            Action.READ,
            Resource.WORKSPACE,
            context(SubscriptionState.SOFT_BLOCKED)
        )
        assertTrue(decisionRead.allowed)

        val decisionWrite = authorizer.authorize(
            principal(),
            Action.UPDATE,
            Resource.WORKSPACE,
            context(SubscriptionState.SOFT_BLOCKED)
        )
        assertFalse(decisionWrite.allowed)
        assertEquals(ReasonCode.DENY_SUBSCRIPTION_SOFT_BLOCKED, decisionWrite.reason)
    }

    @Test
    fun `read only subscription denies write but allows read`() {
        val decisionRead = authorizer.authorize(
            principal(),
            Action.READ,
            Resource.WORKSPACE,
            context(SubscriptionState.READ_ONLY)
        )
        assertTrue(decisionRead.allowed)

        val decisionWrite = authorizer.authorize(
            principal(),
            Action.UPDATE,
            Resource.WORKSPACE,
            context(SubscriptionState.READ_ONLY)
        )
        assertFalse(decisionWrite.allowed)
        assertEquals(ReasonCode.DENY_SUBSCRIPTION_READ_ONLY, decisionWrite.reason)
    }
}
