package com.ideascale.authz.engine.policies

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.Decision
import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.Authorities
import com.ideascale.authz.engine.RelationshipFacts
import com.ideascale.authz.engine.ResourceContext

class DefaultAuthorityPolicy : AuthorityPolicy {
    override fun allowDecisionIfMatched(
        action: Action,
        resource: ResourceRef,
        rc: ResourceContext,
        rf: RelationshipFacts,
        authorities: Authorities
    ): Decision? {
        if (rf.isIdeaOwner && action.id == "idea.edit") {
            return Decision.allow(
                reason = ReasonCode.ALLOW_OWNER,
                details = mapOf("matchedRule" to "idea.edit:owner")
            )
        }

        if ("WORKSPACE_ADMIN" in authorities.workspaceRoles) {
            return Decision.allow(
                reason = ReasonCode.ALLOW_ROLE,
                details = mapOf("matchedRole" to "WORKSPACE_ADMIN")
            )
        }

        if ("CAMPAIGN_MODERATOR" in authorities.campaignRoles && action.id.startsWith("idea.moderate.")) {
            return Decision.allow(
                reason = ReasonCode.ALLOW_ROLE,
                details = mapOf("matchedRole" to "CAMPAIGN_MODERATOR")
            )
        }

        return null
    }
}
