package com.ideascale.commons.authz.engine.catalog

import com.ideascale.commons.authz.engine.dsl.PolicySetBase
import com.ideascale.commons.authz.engine.model.Policy
import com.ideascale.commons.authz.engine.model.RoleLevel
import com.ideascale.commons.authz.context.*
import com.ideascale.commons.authz.decision.ReasonCode
import com.ideascale.commons.authz.resource.ResourceType

/**
 * Policies for Idea resources.
 *
 * Demonstrates:
 * - Membership permissions (role-based access)
 * - Relationship permissions (ownership, group membership)
 * - Forbid policies with attribute conditions
 * - Unless conditions
 *
 * Evaluation order:
 * 1. Forbid policies are evaluated first (forbid overrides permit)
 * 2. Permit policies are evaluated next
 * 3. Default is DENY if no policy matches
 */
object IdeaPolicies : PolicySetBase(ResourceType.IDEA) {

    // ========================================================================
    // PERMIT POLICIES - Membership Permissions (Role-based)
    // ========================================================================

    /**
     * Workspace admin has full access to all ideas.
     */
    val adminFullAccess: Policy = policy(
        permit(
            principal = { hasRole(RoleIds.WORKSPACE_ADMIN, at = RoleLevel.WORKSPACE) },
            action = { `in`(IdeaActionsHierarchy) },
            resource = { any() }
        ).id("idea.admin.full_access")
         .reason(ReasonCode.ALLOW_ROLE)
         .priority(Policy.HIGH_PRIORITY)
         .description("Workspace admin can perform any action on ideas")
    )

    /**
     * Campaign moderator can moderate ideas in their campaign.
     */
    val moderatorCanModerate: Policy = policy(
        permit(
            principal = { hasRole(RoleIds.CAMPAIGN_MODERATOR, at = RoleLevel.CAMPAIGN) },
            action = { `in`(IdeaActionsHierarchy.moderateActions) },
            resource = { any() }
        ).id("idea.moderator.moderate")
         .reason(ReasonCode.ALLOW_ROLE)
         .description("Campaign moderator can moderate ideas")
    )

    /**
     * Community members can view ideas.
     */
    val memberCanView: Policy = policy(
        permit(
            principal = { hasAnyRole(RoleIds.COMMUNITY_MEMBER, RoleIds.WORKSPACE_MEMBER) },
            action = { `in`(IdeaActionsHierarchy.readActions) },
            resource = { any() }
        ).id("idea.member.view")
         .reason(ReasonCode.ALLOW_ROLE)
         .description("Community/workspace members can view ideas")
    )

    /**
     * Community members can create ideas.
     */
    val memberCanCreate: Policy = policy(
        permit(
            principal = { hasRole(RoleIds.COMMUNITY_MEMBER, at = RoleLevel.COMMUNITY) },
            action = { eq(IdeaActionsHierarchy.create) },
            resource = { any() }
        ).id("idea.member.create")
         .reason(ReasonCode.ALLOW_ROLE)
         .description("Community members can create ideas")
    )

    // ========================================================================
    // PERMIT POLICIES - Relationship Permissions (Ownership)
    // ========================================================================

    /**
     * Idea owner can edit their own idea.
     */
    val ownerCanEdit: Policy = policy(
        (permit(
            principal = { authenticated() },
            action = { eq(IdeaActionsHierarchy.edit) },
            resource = { any() }
        ) `when` {
            relationship { isIdeaOwner() }
        }).id("idea.owner.edit")
          .reason(ReasonCode.ALLOW_OWNER)
          .description("Idea owner can edit their own idea")
    )

    /**
     * Idea owner can delete their own idea.
     */
    val ownerCanDelete: Policy = policy(
        (permit(
            principal = { authenticated() },
            action = { eq(IdeaActionsHierarchy.delete) },
            resource = { any() }
        ) `when` {
            relationship { isIdeaOwner() }
        }).id("idea.owner.delete")
          .reason(ReasonCode.ALLOW_OWNER)
          .description("Idea owner can delete their own idea")
    )

    // ========================================================================
    // PERMIT POLICIES - Relationship Permissions (Group-based)
    // ========================================================================

    /**
     * Users with group access can view ideas shared with their groups.
     */
    val groupMemberCanView: Policy = policy(
        (permit(
            principal = { authenticated() },
            action = { `in`(IdeaActionsHierarchy.readActions) },
            resource = { any() }
        ) `when` {
            relationship { inAnyGroup() }
        }).id("idea.group.view")
          .reason(ReasonCode.ALLOW_RELATIONSHIP)
          .description("Group members can view ideas shared with their groups")
    )

    // ========================================================================
    // FORBID POLICIES - Attribute Conditions
    // ========================================================================

    /**
     * Locked ideas cannot be edited or deleted.
     * Exception: Moderators can still unlock.
     */
    val lockedIdeaDenyWrite: Policy = policy(
        (forbid(
            principal = { any() },
            action = { `in`(IdeaActionsHierarchy.writeActions) },
            resource = { any() }
        ) `when` {
            attribute { ideaState(IdeaState.LOCKED) }
        } unless {
            role { hasRole(RoleIds.CAMPAIGN_MODERATOR, at = RoleLevel.CAMPAIGN) }
        }).id("idea.locked.deny_write")
          .reason(ReasonCode.DENY_IDEA_LOCKED)
          .priority(Policy.HIGH_PRIORITY)
          .description("Locked ideas cannot be edited or deleted (except by moderators)")
    )

    /**
     * Archived ideas cannot be modified.
     */
    val archivedIdeaDenyWrite: Policy = policy(
        (forbid(
            principal = { any() },
            action = { `in`(IdeaActionsHierarchy.writeActions) },
            resource = { any() }
        ) `when` {
            attribute { ideaState(IdeaState.ARCHIVED) }
        }).id("idea.archived.deny_write")
          .reason(ReasonCode.DENY_IDEA_ARCHIVED)
          .priority(Policy.HIGH_PRIORITY)
          .description("Archived ideas cannot be modified")
    )

    /**
     * Ideas in expired campaigns cannot be modified.
     */
    val expiredCampaignDenyWrite: Policy = policy(
        (forbid(
            principal = { any() },
            action = { `in`(IdeaActionsHierarchy.writeActions) },
            resource = { any() }
        ) `when` {
            attribute { campaignState(CampaignState.EXPIRED) }
        }).id("idea.campaign_expired.deny_write")
          .reason(ReasonCode.DENY_CAMPAIGN_EXPIRED)
          .priority(Policy.HIGH_PRIORITY)
          .description("Ideas in expired campaigns cannot be modified")
    )

    /**
     * Ideas in read-only campaigns cannot be modified.
     */
    val readOnlyCampaignDenyWrite: Policy = policy(
        (forbid(
            principal = { any() },
            action = { `in`(IdeaActionsHierarchy.writeActions) },
            resource = { any() }
        ) `when` {
            attribute { campaignState(CampaignState.READONLY) }
        }).id("idea.campaign_readonly.deny_write")
          .reason(ReasonCode.DENY_RESOURCE_READONLY)
          .priority(Policy.HIGH_PRIORITY)
          .description("Ideas in read-only campaigns cannot be modified")
    )
}
