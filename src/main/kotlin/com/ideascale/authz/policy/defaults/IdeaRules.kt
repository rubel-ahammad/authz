package com.ideascale.authz.policy.defaults

import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.core.ResourceType
import com.ideascale.authz.context.CampaignState
import com.ideascale.authz.engine.EvaluationContext
import com.ideascale.authz.context.IdeaState
import com.ideascale.authz.context.RoleIds
import com.ideascale.authz.core.ActionGroup
import com.ideascale.authz.policy.rules.AllowRule
import com.ideascale.authz.policy.rules.DenyRule
import com.ideascale.authz.policy.rules.Target

object IdeaRules {
    fun resourceContextDenyRules(): List<DenyRule> = emptyList()

    fun relationshipDenyRules(): List<DenyRule> = emptyList()

    fun attributeDenyRules(): List<DenyRule> = listOf(
        denyWritesWhenCampaignReadOnlyOrExpired(),
        denyWritesWhenIdeaLockedOrArchived()
    )

    fun roleAllowRules(): List<AllowRule> = listOf(
        allowIdeaWriteForOwner(),
        allowIdeaModerationForCampaignModerator(),
        allowAllForWorkspaceAdmin()
    )

    private fun denyWritesWhenCampaignReadOnlyOrExpired(): DenyRule =
        DenyRule(
            id = "idea.campaign.state.deny_write",
            target = Target(ResourceType.IDEA, ActionGroup.WRITE)
        ) { ec: EvaluationContext ->
            val facts = ec.attributeContext ?: return@DenyRule null
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
            val facts = ec.attributeContext ?: return@DenyRule null
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
            val relationshipContext = ec.relationshipContext ?: return@AllowRule null
            if (!relationshipContext.isIdeaOwner) return@AllowRule null

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
            val roleContext = ec.roleContext ?: return@AllowRule null
            if (RoleIds.CAMPAIGN_MODERATOR !in roleContext.campaignRoles) return@AllowRule null

            ec.allow(
                reason = ReasonCode.ALLOW_ROLE,
                details = mapOf(
                    "matchedRuleId" to "idea.moderate.allow_campaign_moderator",
                    "matchedRole" to RoleIds.CAMPAIGN_MODERATOR.value
                )
            )
        }

    private fun allowAllForWorkspaceAdmin(): AllowRule =
        AllowRule(
            id = "workspace.admin.allow_all",
            target = Target(ResourceType.IDEA, ActionGroup.ADMIN)
        ) { ec: EvaluationContext ->
            val roleContext = ec.roleContext ?: return@AllowRule null
            if (RoleIds.WORKSPACE_ADMIN !in roleContext.workspaceRoles) return@AllowRule null

            ec.allow(
                reason = ReasonCode.ALLOW_ROLE,
                details = mapOf(
                    "matchedRuleId" to "workspace.admin.allow_all",
                    "matchedRole" to RoleIds.WORKSPACE_ADMIN.value
                )
            )
        }
}
