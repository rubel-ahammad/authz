package com.ideascale.authz.engine

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.AuthzContext
import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.core.ResourceType
import com.ideascale.authz.core.Subject
import kotlin.test.Test
import kotlin.test.assertEquals

class TenantBindingTest {
    @Test
    fun `resource workspace mismatch denies`() {
        val calls = mutableListOf<String>()
        val authorizer = buildDefaultPipelineAuthorizer(
            PipelineDependencies(
                globalDenyProvider = RecordingGlobalDenyProvider(calls),
                resourceContextResolver = RecordingResourceContextResolver(calls, ResourceContext("w2")),
                relationshipProvider = RecordingRelationshipProvider(calls, RelationshipFacts(true)),
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

        assertEquals(ReasonCode.DENY_TENANT_MISMATCH, decision.reason)
        assertEquals(listOf("GlobalDeny", "ResourceContext"), calls)
    }
}
