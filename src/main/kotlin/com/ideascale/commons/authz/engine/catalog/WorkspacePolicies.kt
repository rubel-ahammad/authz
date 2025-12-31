package com.ideascale.commons.authz.engine.catalog

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.engine.dsl.PolicySetBase
import com.ideascale.commons.authz.engine.model.Policy
import com.ideascale.commons.authz.resource.Resource

/**
 * Policies for Workspace resources.
 */
object WorkspacePolicies : PolicySetBase(Resource.WORKSPACE) {

    /**
     * Any principal can read public workspaces.
     */
    val anyoneCanReadPublicWorkspace: Policy = policy(
        (permit(
            principal = { any() },
            action = { eq(Action.READ) },
            resource = { ofType(Resource.WORKSPACE) }
        ) `when` {
            attribute { workspacePublic() }
        }).id("workspace.public.any.read")
          .reason(ReasonCode.ALLOW_SYSTEM)
          .description("All principals can read public workspaces")
    )

    /**
     * Anonymous principals cannot read private workspaces.
     */
    val anonymousCannotReadPrivateWorkspace: Policy = policy(
        (forbid(
            principal = { anonymous() },
            action = { eq(Action.READ) },
            resource = { ofType(Resource.WORKSPACE) }
        ) `when` {
            attribute { workspacePrivate() }
        }).id("workspace.private.anonymous.read")
          .reason(ReasonCode.DENY_WORKSPACE_PRIVATE)
          .description("Anonymous principals cannot read private workspaces")
    )
}
