package com.ideascale.authz.engine

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.AuthzContext
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.core.ResourceType
import com.ideascale.authz.core.Subject
import kotlin.test.Test
import kotlin.test.assertEquals

class PipelineOrderTest {
    @Test
    fun `pipeline runs evaluators in order`() {
        val calls = mutableListOf<String>()
        val authorizer = buildDefaultPipelineAuthorizer(
            PipelineDependencies(
                globalDenyProvider = RecordingGlobalDenyProvider(calls),
                resourceContextResolver = RecordingResourceContextResolver(calls, ResourceContext("w1")),
                relationshipProvider = RecordingRelationshipProvider(
                    calls,
                    RelationshipFacts(isWorkspaceMember = true)
                ),
                attributeProvider = RecordingAttributeProvider(calls, AttributeFacts()),
                authorityProvider = RecordingAuthorityProvider(calls, Authorities())
            )
        )

        val decision = authorizer.authorize(
            subject = Subject(workspaceId = "w1", memberId = "m1"),
            action = Action("idea.read"),
            resource = ResourceRef(ResourceType.IDEA, "idea-1"),
            context = AuthzContext()
        )

        assertEquals(
            listOf("GlobalDeny", "ResourceContext", "Relationship", "Attribute", "Authority"),
            calls
        )
        assertEquals("idea.read", decision.details["action"])
    }
}
