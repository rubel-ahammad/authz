package com.ideascale.authz.engine

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.AuthzContext
import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.core.ResourceType
import com.ideascale.authz.core.Subject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class ReadonlyConstraintTest {
    @Test
    fun `readonly campaign denies mutation before allow rules`() {
        val calls = mutableListOf<String>()
        val authorizer = buildDefaultPipelineAuthorizer(
            PipelineDependencies(
                globalDenyProvider = RecordingGlobalDenyProvider(calls),
                resourceContextResolver = RecordingResourceContextResolver(calls, ResourceContext("w1")),
                relationshipProvider = RecordingRelationshipProvider(
                    calls,
                    RelationshipFacts(isWorkspaceMember = true)
                ),
                attributeProvider = RecordingAttributeProvider(
                    calls,
                    AttributeFacts(campaignState = "READONLY")
                ),
                authorityProvider = RecordingAuthorityProvider(
                    calls,
                    Authorities(workspaceRoles = setOf("WORKSPACE_ADMIN"))
                )
            )
        )

        val decision = authorizer.authorize(
            subject = Subject(workspaceId = "w1", memberId = "m1"),
            action = Action("idea.edit"),
            resource = ResourceRef(ResourceType.IDEA, "idea-1"),
            context = AuthzContext()
        )

        assertEquals(ReasonCode.DENY_RESOURCE_READONLY, decision.reason)
        assertFalse(calls.contains("Authority"))
    }
}
