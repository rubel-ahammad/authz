package com.ideascale.commons.authz

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.engine.PolicyEngineAuthorizer
import com.ideascale.commons.authz.engine.catalog.GlobalPolicies
import com.ideascale.commons.authz.engine.catalog.WorkspacePolicies
import com.ideascale.commons.authz.resource.Resource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WorkspaceAnonymousAccessTest {

    @Test
    fun `anonymous can read public workspace`() {
        val authorizer = PolicyEngineAuthorizer(
            GlobalPolicies.toSet(),
            WorkspacePolicies.toSet()
        )

        val workspaceId = "w-1"
        val principal = Principal(workspaceId = workspaceId, memberId = null)
        val context = AuthorizationContext(
            resource = WorkspaceContext(workspaceId),
            attributes = AttributeContext(
                workspace = WorkspaceAttrs(
                    subscription = SubscriptionAttrs(SubscriptionState.ACTIVE),
                    network = NetworkAttrs(IpRestrictionResult.Allowed),
                    emailDomain = EmailDomainAttrs(),
                    flags = WorkspaceFlags(isPublic = true)
                ),
                member = MemberAttrs(MemberStatus.MEMBER),
                request = RequestAttrs(ip = "203.0.113.1", channel = Channel.PUBLIC_API)
            )
        )

        val readDecision = authorizer.authorize(
            principal,
            Action.READ,
            Resource.WORKSPACE,
            context
        )
        assertTrue(readDecision.allowed)
    }

    @Test
    fun `authenticated can read public workspace`() {
        val authorizer = PolicyEngineAuthorizer(
            GlobalPolicies.toSet(),
            WorkspacePolicies.toSet()
        )

        val workspaceId = "w-1"
        val principal = Principal(workspaceId = workspaceId, memberId = "m-1")
        val context = AuthorizationContext(
            resource = WorkspaceContext(workspaceId),
            attributes = AttributeContext(
                workspace = WorkspaceAttrs(
                    subscription = SubscriptionAttrs(SubscriptionState.ACTIVE),
                    network = NetworkAttrs(IpRestrictionResult.Allowed),
                    emailDomain = EmailDomainAttrs(),
                    flags = WorkspaceFlags(isPublic = true)
                ),
                member = MemberAttrs(MemberStatus.MEMBER),
                request = RequestAttrs(ip = "203.0.113.1", channel = Channel.PUBLIC_API)
            )
        )

        val readDecision = authorizer.authorize(
            principal,
            Action.READ,
            Resource.WORKSPACE,
            context
        )
        assertTrue(readDecision.allowed)
    }

    @Test
    fun `anonymous cannot read private workspace`() {
        val authorizer = PolicyEngineAuthorizer(
            GlobalPolicies.toSet(),
            WorkspacePolicies.toSet()
        )

        val workspaceId = "w-1"
        val principal = Principal(workspaceId = workspaceId, memberId = null)
        val context = AuthorizationContext(
            resource = WorkspaceContext(workspaceId),
            attributes = AttributeContext(
                workspace = WorkspaceAttrs(
                    subscription = SubscriptionAttrs(SubscriptionState.ACTIVE),
                    network = NetworkAttrs(IpRestrictionResult.Allowed),
                    emailDomain = EmailDomainAttrs(),
                    flags = WorkspaceFlags(isPublic = false)
                ),
                member = MemberAttrs(MemberStatus.MEMBER),
                request = RequestAttrs(ip = "203.0.113.1", channel = Channel.PUBLIC_API)
            )
        )

        val decision = authorizer.authorize(
            principal,
            Action.READ,
            Resource.WORKSPACE,
            context
        )
        assertFalse(decision.allowed)
    }

    @Test
    fun `anonymous private workspace read returns private reason`() {
        val authorizer = PolicyEngineAuthorizer(
            GlobalPolicies.toSet(),
            WorkspacePolicies.toSet()
        )

        val workspaceId = "w-1"
        val principal = Principal(workspaceId = workspaceId, memberId = null)
        val context = AuthorizationContext(
            resource = WorkspaceContext(workspaceId),
            attributes = AttributeContext(
                workspace = WorkspaceAttrs(
                    subscription = SubscriptionAttrs(SubscriptionState.ACTIVE),
                    network = NetworkAttrs(IpRestrictionResult.Allowed),
                    emailDomain = EmailDomainAttrs(),
                    flags = WorkspaceFlags(isPublic = false)
                ),
                member = MemberAttrs(MemberStatus.MEMBER),
                request = RequestAttrs(ip = "203.0.113.1", channel = Channel.PUBLIC_API)
            )
        )

        val decision = authorizer.authorize(
            principal,
            Action.READ,
            Resource.WORKSPACE,
            context
        )
        assertFalse(decision.allowed)
        assertEquals(ReasonCode.DENY_WORKSPACE_PRIVATE, decision.reason)
    }
}
