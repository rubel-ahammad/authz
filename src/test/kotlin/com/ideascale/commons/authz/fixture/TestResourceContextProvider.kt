package com.ideascale.commons.authz.fixture

import com.ideascale.commons.authz.context.CommunityContext
import com.ideascale.commons.authz.context.ResourceContext
import com.ideascale.commons.authz.context.WorkspaceContext
import com.ideascale.commons.authz.context.provider.ResourceContextProvider
import com.ideascale.commons.authz.core.ResourceRef

class TestResourceContextProvider(
    private val contexts: Map<String, ResourceContext> = emptyMap(),
    private val defaultWorkspaceId: String = TestSubjects.WORKSPACE_ID
) : ResourceContextProvider {

    override fun load(resource: ResourceRef): ResourceContext {
        return contexts[resource.id]
            ?: WorkspaceContext(workspaceId = defaultWorkspaceId)
    }

    companion object {
        fun forWorkspace(workspaceId: String = TestSubjects.WORKSPACE_ID): TestResourceContextProvider {
            return TestResourceContextProvider(
                contexts = mapOf(workspaceId to WorkspaceContext(workspaceId)),
                defaultWorkspaceId = workspaceId
            )
        }

        fun forCommunity(
            communityId: String,
            workspaceId: String = TestSubjects.WORKSPACE_ID
        ): TestResourceContextProvider {
            return TestResourceContextProvider(
                contexts = mapOf(communityId to CommunityContext(workspaceId, communityId)),
                defaultWorkspaceId = workspaceId
            )
        }
    }
}
