package com.ideascale.commons.authz.policy.catalog

import com.ideascale.commons.authz.core.ActionGroup
import com.ideascale.commons.authz.core.ReasonCode
import com.ideascale.commons.authz.core.ResourceType
import com.ideascale.commons.authz.context.CampaignState
import com.ideascale.commons.authz.engine.EvaluationContext
import com.ideascale.commons.authz.context.IdeaState
import com.ideascale.commons.authz.context.RoleIds
import com.ideascale.commons.authz.policy.dsl.allow
import com.ideascale.commons.authz.policy.dsl.deny
import com.ideascale.commons.authz.policy.rule.AllowRule
import com.ideascale.commons.authz.policy.rule.DenyRule

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
        deny {
            id("idea.campaign.state.deny_write")
            target(ResourceType.IDEA, ActionGroup.WRITE)
            condition { ec: EvaluationContext ->
                val facts = ec.attributeContext ?: return@condition null
                when (facts.campaign?.state) {
                    CampaignState.READONLY -> ReasonCode.DENY_RESOURCE_READONLY
                    CampaignState.EXPIRED -> ReasonCode.DENY_CAMPAIGN_EXPIRED
                    else -> null
                }
            }
        }

    private fun denyWritesWhenIdeaLockedOrArchived(): DenyRule =
        deny {
            id("idea.state.deny_write")
            target(ResourceType.IDEA, ActionGroup.WRITE)
            condition { ec: EvaluationContext ->
                val facts = ec.attributeContext ?: return@condition null
                when (facts.idea?.state) {
                    IdeaState.LOCKED -> ReasonCode.DENY_IDEA_LOCKED
                    IdeaState.ARCHIVED -> ReasonCode.DENY_IDEA_ARCHIVED
                    else -> null
                }
            }
        }

    private fun allowIdeaWriteForOwner(): AllowRule =
        allow {
            id("idea.write.allow_owner")
            target(ResourceType.IDEA, ActionGroup.WRITE)
            condition { ec: EvaluationContext ->
                val relationshipContext = ec.relationshipContext ?: return@condition null
                if (!relationshipContext.isIdeaOwner) return@condition null

                ec.allow(
                    reason = ReasonCode.ALLOW_OWNER,
                    details = mapOf("matchedRuleId" to "idea.write.allow_owner")
                )
            }
        }

    private fun allowIdeaModerationForCampaignModerator(): AllowRule =
        allow {
            id("idea.moderate.allow_campaign_moderator")
            target(ResourceType.IDEA, ActionGroup.MODERATE)
            condition { ec: EvaluationContext ->
                val roleContext = ec.roleContext ?: return@condition null
                if (RoleIds.CAMPAIGN_MODERATOR !in roleContext.campaignRoles) return@condition null

                ec.allow(
                    reason = ReasonCode.ALLOW_ROLE,
                    details = mapOf(
                        "matchedRuleId" to "idea.moderate.allow_campaign_moderator",
                        "matchedRole" to RoleIds.CAMPAIGN_MODERATOR.value
                    )
                )
            }
        }

    private fun allowAllForWorkspaceAdmin(): AllowRule =
        allow {
            id("workspace.admin.allow_all")
            target(ResourceType.IDEA, ActionGroup.ADMIN)
            condition { ec: EvaluationContext ->
                val roleContext = ec.roleContext ?: return@condition null
                if (RoleIds.WORKSPACE_ADMIN !in roleContext.workspaceRoles) return@condition null

                ec.allow(
                    reason = ReasonCode.ALLOW_ROLE,
                    details = mapOf(
                        "matchedRuleId" to "workspace.admin.allow_all",
                        "matchedRole" to RoleIds.WORKSPACE_ADMIN.value
                    )
                )
            }
        }
}
