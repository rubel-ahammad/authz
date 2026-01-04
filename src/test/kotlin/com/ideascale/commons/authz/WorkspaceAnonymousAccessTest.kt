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

    private val workspaceId = 1L

    private fun context(isPublic: Boolean, principalContext: PrincipalContext): AuthorizationContext =
        AuthorizationContext(
            principal = principalContext,
            resource = WorkspaceContext(
                id = workspaceId,
                workspace = WorkspaceAttributes(
                    id = workspaceId,
                    subscriptionState = SubscriptionState.ACTIVE,
                    isPublic = isPublic
                )
            ),
            environment = EnvironmentContext(ip = "203.0.113.1", channel = Channel.PUBLIC_API)
        )

    @Test
    fun `anonymous can read public workspace`() {
        val authorizer = PolicyEngineAuthorizer(
            GlobalPolicies.toSet(),
            WorkspacePolicies.toSet()
        )

        val principal = Principal.anonymous(workspaceId)
        val context = context(isPublic = true, principalContext = PrincipalContext.ANONYMOUS)

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

        val principal = Principal.user(id = 42L, workspaceId = workspaceId)
        val context = context(isPublic = true, principalContext = PrincipalContext())

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

        val principal = Principal.anonymous(workspaceId)
        val context = context(isPublic = false, principalContext = PrincipalContext.ANONYMOUS)

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

        val principal = Principal.anonymous(workspaceId)
        val context = context(isPublic = false, principalContext = PrincipalContext.ANONYMOUS)

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
