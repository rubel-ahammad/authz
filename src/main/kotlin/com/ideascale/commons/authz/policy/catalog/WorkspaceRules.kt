package com.ideascale.commons.authz.policy.catalog

import com.ideascale.commons.authz.core.ActionGroup
import com.ideascale.commons.authz.core.ReasonCode
import com.ideascale.commons.authz.core.ResourceType
import com.ideascale.commons.authz.context.RoleIds
import com.ideascale.commons.authz.engine.EvaluationContext
import com.ideascale.commons.authz.policy.dsl.allow
import com.ideascale.commons.authz.policy.dsl.deny
import com.ideascale.commons.authz.policy.rule.DenyRule
import com.ideascale.commons.authz.policy.rule.AllowRule

object WorkspaceRules {

    fun attributeDenyRules(): List<DenyRule> =
        ActionGroup.entries.map { denyAnonymousWhenWorkspacePrivate(it) }

    fun roleAllowRules(): List<AllowRule> = listOf(
        allowReadForAnyRole(),
        allowWriteForWorkspaceAdmin()
    )

    private fun denyAnonymousWhenWorkspacePrivate(actionGroup: ActionGroup): DenyRule =
        deny {
            id("workspace.private.deny_anonymous.${actionGroup.name.lowercase()}")
            target(ResourceType.WORKSPACE, actionGroup)
            condition { ec: EvaluationContext ->
                val facts = ec.attributeContext ?: return@condition null
                if (facts.workspace.flags.isPublic) return@condition null
                if (!ec.request.subject.isAnonymous) return@condition null

                ReasonCode.DENY_WORKSPACE_PRIVATE
            }
        }

    private fun allowReadForAnyRole(): AllowRule =
        allow {
            id("workspace.read.allow_any_role")
            target(ResourceType.WORKSPACE, ActionGroup.READ)
            condition { ec: EvaluationContext ->
                val roleContext = ec.roleContext ?: return@condition null
                val hasAnyRole = RoleIds.ANONYMOUS in roleContext.workspaceRoles ||
                        RoleIds.WORKSPACE_MEMBER in roleContext.workspaceRoles ||
                        RoleIds.WORKSPACE_ADMIN in roleContext.workspaceRoles

                if (!hasAnyRole) return@condition null

                ec.allow(
                    reason = ReasonCode.ALLOW_ROLE,
                    details = mapOf("matchedRuleId" to "workspace.read.allow_any_role")
                )
            }
        }

    private fun allowWriteForWorkspaceAdmin(): AllowRule =
        allow {
            id("workspace.write.allow_workspace_admin")
            target(ResourceType.WORKSPACE, ActionGroup.WRITE)
            condition { ec: EvaluationContext ->
                val roleContext = ec.roleContext ?: return@condition null
                if (RoleIds.WORKSPACE_ADMIN !in roleContext.workspaceRoles) return@condition null

                ec.allow(
                    reason = ReasonCode.ALLOW_ROLE,
                    details = mapOf(
                        "matchedRuleId" to "workspace.write.allow_workspace_admin",
                        "matchedRole" to RoleIds.WORKSPACE_ADMIN.value
                    )
                )
            }
        }
}
