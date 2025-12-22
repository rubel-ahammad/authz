package com.ideascale.authz.engine.policies

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.AttributeFacts
import com.ideascale.authz.engine.RelationshipFacts
import com.ideascale.authz.engine.ResourceContext

class DefaultAttributeConstraintPolicy : AttributeConstraintPolicy {
    override fun denyReasonIfForbidden(
        action: Action,
        resource: ResourceRef,
        rc: ResourceContext,
        rf: RelationshipFacts,
        af: AttributeFacts
    ): ReasonCode? {
        val actionId = action.id

        if (af.campaignState == "READONLY" && actionId in readonlyBlockedActions()) {
            return ReasonCode.DENY_RESOURCE_READONLY
        }

        if (af.campaignState == "EXPIRED" && isMutationAction(actionId)) {
            return ReasonCode.DENY_CAMPAIGN_EXPIRED
        }

        if (af.subscriptionState == "SOFT_BLOCKED" && isMutationAction(actionId)) {
            return ReasonCode.DENY_SUBSCRIPTION_BLOCKED
        }

        return null
    }

    private fun readonlyBlockedActions(): Set<String> = setOf(
        "idea.create",
        "idea.edit",
        "idea.delete",
        "campaign.update",
        "campaign.delete",
        "campaign.launch"
    )

    private fun isMutationAction(actionId: String): Boolean {
        val tokens = listOf(
            ".create",
            ".edit",
            ".update",
            ".delete",
            ".launch",
            ".close",
            ".archive",
            ".moderate."
        )
        return tokens.any { actionId.contains(it) }
    }
}
