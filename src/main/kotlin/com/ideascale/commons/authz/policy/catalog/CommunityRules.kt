package com.ideascale.commons.authz.policy.catalog

import com.ideascale.commons.authz.core.ActionGroup
import com.ideascale.commons.authz.core.ReasonCode
import com.ideascale.commons.authz.core.ResourceType
import com.ideascale.commons.authz.context.RoleIds
import com.ideascale.commons.authz.engine.EvaluationContext
import com.ideascale.commons.authz.policy.dsl.allow
import com.ideascale.commons.authz.policy.rule.AllowRule

object CommunityRules {

    fun roleAllowRules(): List<AllowRule> = listOf(
        allowReadForAnyRole(),
        allowWriteForAdmin()
    )

    private fun allowReadForAnyRole(): AllowRule =
        allow {
            id("community.read.allow_any_role")
            target(ResourceType.COMMUNITY, ActionGroup.READ)
            condition { ec: EvaluationContext ->
                val roleContext = ec.roleContext ?: return@condition null
                val hasAnyRole = RoleIds.ANONYMOUS in roleContext.workspaceRoles ||
                        RoleIds.COMMUNITY_MEMBER in roleContext.communityRoles ||
                        RoleIds.ADMIN in roleContext.communityRoles

                if (!hasAnyRole) return@condition null

                ec.allow(
                    reason = ReasonCode.ALLOW_ROLE,
                    details = mapOf("matchedRuleId" to "community.read.allow_any_role")
                )
            }
        }

    private fun allowWriteForAdmin(): AllowRule =
        allow {
            id("community.write.allow_admin")
            target(ResourceType.COMMUNITY, ActionGroup.WRITE)
            condition { ec: EvaluationContext ->
                val roleContext = ec.roleContext ?: return@condition null
                if (RoleIds.ADMIN !in roleContext.communityRoles) return@condition null

                ec.allow(
                    reason = ReasonCode.ALLOW_ROLE,
                    details = mapOf(
                        "matchedRuleId" to "community.write.allow_admin",
                        "matchedRole" to RoleIds.ADMIN.value
                    )
                )
            }
        }
}
