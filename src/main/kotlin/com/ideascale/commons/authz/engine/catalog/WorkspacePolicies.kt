package com.ideascale.commons.authz.engine.catalog

import com.ideascale.commons.authz.engine.dsl.PolicySetBase
import com.ideascale.commons.authz.engine.model.Policy
import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.resource.ResourceType

/**
 * Policies for Workspace resources.
 */
object WorkspacePolicies : PolicySetBase(ResourceType.WORKSPACE) {

    /**
     * Anonymous principals can read public workspaces.
     */
    val anonymousCanReadPublicWorkspace: Policy = policy(
        (permit(
            principal = { anonymous() },
            action = { eq(WorkspaceActionsHierarchy.read) },
            resource = { ofType(ResourceType.WORKSPACE) }
        ) `when` {
            attribute { workspacePublic() }
        }).id("workspace.public.anonymous.read")
          .reason(ReasonCode.ALLOW_SYSTEM)
          .description("Anonymous principals can read public workspaces")
    )
}
