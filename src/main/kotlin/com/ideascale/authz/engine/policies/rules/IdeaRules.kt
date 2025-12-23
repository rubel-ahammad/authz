package com.ideascale.authz.engine.policies.rules

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.core.ResourceType
import com.ideascale.authz.engine.CampaignState
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.engine.IdeaState
import com.ideascale.authz.engine.RoleIds
import com.ideascale.authz.engine.rules.ActionGroup
import com.ideascale.authz.engine.rules.AllowRule
import com.ideascale.authz.engine.rules.DenyRule
import com.ideascale.authz.engine.rules.Target

object IdeaRules {
    fun resourceContextDenyRules(): List<DenyRule> = emptyList()

    fun relationshipDenyRules(): List<DenyRule> = emptyList()

    fun attributeDenyRules(): List<DenyRule> = listOf(
        denyWritesWhenWorkspaceReadOnly(),
        denyWritesWhenCampaignReadOnlyOrExpired(),
        denyWritesWhenIdeaLockedOrArchived()
    )

    fun authorityAllowRules(): List<AllowRule> = listOf(
        allowIdeaWriteForOwner(),
        allowIdeaModerationForCampaignModerator(),
        allowAllForWorkspaceAdmin()
    )

    private fun denyWritesWhenWorkspaceReadOnly(): DenyRule =
        DenyRule(
            id = "idea.workspace.readonly.deny_write",
            target = Target(ResourceType.IDEA, ActionGroup.WRITE)
        ) { ec: EvaluationContext ->
            val facts = ec.attributeFacts ?: return@DenyRule null
            if (facts.workspace.flags.isReadOnlyMode) ReasonCode.DENY_WORKSPACE_READONLY else null
        }

    private fun denyWritesWhenCampaignReadOnlyOrExpired(): DenyRule =
        DenyRule(
            id = "idea.campaign.state.deny_write",
            target = Target(ResourceType.IDEA, ActionGroup.WRITE)
        ) { ec: EvaluationContext ->
            val facts = ec.attributeFacts ?: return@DenyRule null
            when (facts.campaign?.state) {
                CampaignState.READONLY -> ReasonCode.DENY_RESOURCE_READONLY
                CampaignState.EXPIRED -> ReasonCode.DENY_CAMPAIGN_EXPIRED
                else -> null
            }
        }

    private fun denyWritesWhenIdeaLockedOrArchived(): DenyRule =
        DenyRule(
            id = "idea.state.deny_write",
            target = Target(ResourceType.IDEA, ActionGroup.WRITE)
        ) { ec: EvaluationContext ->
            val facts = ec.attributeFacts ?: return@DenyRule null
            when (facts.idea?.state) {
                IdeaState.LOCKED -> ReasonCode.DENY_IDEA_LOCKED
                IdeaState.ARCHIVED -> ReasonCode.DENY_IDEA_ARCHIVED
                else -> null
            }
        }

    private fun allowIdeaWriteForOwner(): AllowRule =
        AllowRule(
            id = "idea.write.allow_owner",
            target = Target(ResourceType.IDEA, ActionGroup.WRITE)
        ) { ec: EvaluationContext ->
            val rf = ec.relationshipFacts ?: return@AllowRule null
            if (!rf.isIdeaOwner) return@AllowRule null

            ec.allow(
                reason = ReasonCode.ALLOW_OWNER,
                details = mapOf("matchedRuleId" to "idea.write.allow_owner")
            )
        }

    private fun allowIdeaModerationForCampaignModerator(): AllowRule =
        AllowRule(
            id = "idea.moderate.allow_campaign_moderator",
            target = Target(ResourceType.IDEA, ActionGroup.MODERATE)
        ) { ec: EvaluationContext ->
            val rf = ec.relationshipFacts ?: return@AllowRule null
            if (!rf.isCampaignModerator) return@AllowRule null

            ec.allow(
                reason = ReasonCode.ALLOW_ROLE,
                details = mapOf(
                    "matchedRuleId" to "idea.moderate.allow_campaign_moderator",
                    "matchedRole" to "CAMPAIGN_MODERATOR"
                )
            )
        }

    private fun allowAllForWorkspaceAdmin(): AllowRule =
        AllowRule(
            id = "workspace.admin.allow_all",
            target = Target(ResourceType.IDEA, ActionGroup.ADMIN)
        ) { ec: EvaluationContext ->
            val authorities = ec.authorities ?: return@AllowRule null
            if (RoleIds.WORKSPACE_ADMIN !in authorities.workspaceRoles) return@AllowRule null

            ec.allow(
                reason = ReasonCode.ALLOW_ROLE,
                details = mapOf(
                    "matchedRuleId" to "workspace.admin.allow_all",
                    "matchedRole" to RoleIds.WORKSPACE_ADMIN.value
                )
            )
        }
}
