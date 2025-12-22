package com.ideascale.authz.engine

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.AuthzContext
import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.core.ResourceType
import com.ideascale.authz.core.Subject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OwnerAllowTest {
    @Test
    fun `idea owner can edit`() {
        val calls = mutableListOf<String>()
        val authorizer = buildDefaultPipelineAuthorizer(
            PipelineDependencies(
                globalDenyProvider = RecordingGlobalDenyProvider(calls),
                resourceContextResolver = RecordingResourceContextResolver(calls, ResourceContext("w1")),
                relationshipProvider = RecordingRelationshipProvider(
                    calls,
                    RelationshipFacts(isWorkspaceMember = true, isIdeaOwner = true)
                ),
                attributeProvider = RecordingAttributeProvider(calls, AttributeFacts()),
                authorityProvider = RecordingAuthorityProvider(calls, Authorities())
            )
        )

        val decision = authorizer.authorize(
            subject = Subject(workspaceId = "w1", memberId = "m1"),
            action = Action("idea.edit"),
            resource = ResourceRef(ResourceType.IDEA, "idea-1"),
            context = AuthzContext()
        )

        assertTrue(decision.allowed)
        assertEquals(ReasonCode.ALLOW_OWNER, decision.reason)
    }
}
