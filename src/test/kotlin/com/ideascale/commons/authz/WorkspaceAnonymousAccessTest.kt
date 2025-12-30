package com.ideascale.commons.authz

import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.engine.PolicyEngineAuthorizer
import com.ideascale.commons.authz.engine.catalog.GlobalPolicies
import com.ideascale.commons.authz.engine.catalog.WorkspaceActionsHierarchy
import com.ideascale.commons.authz.engine.catalog.WorkspacePolicies
import com.ideascale.commons.authz.resource.Resource
import com.ideascale.commons.authz.resource.ResourceType
import kotlin.test.Test
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
        val resource = Resource(ResourceType.WORKSPACE, workspaceId)
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
            WorkspaceActionsHierarchy.read,
            resource,
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
        val resource = Resource(ResourceType.WORKSPACE, workspaceId)
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
            WorkspaceActionsHierarchy.read,
            resource,
            context
        )
        assertFalse(decision.allowed)
    }
}
