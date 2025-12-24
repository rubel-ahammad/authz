package com.ideascale.commons.authz.action

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.action.ActionGroup

object ActionSemantics {
    // Explicit action → group registry (single source of truth)
    private val actionGroups: Map<String, ActionGroup> = buildMap {
        // READ actions
        put(WorkspaceActions.READ.id, ActionGroup.READ)
        put(CommunityActions.READ.id, ActionGroup.READ)
        put(IdeaActions.READ.id, ActionGroup.READ)
        put(IdeaActions.LIST.id, ActionGroup.READ)
        put(CampaignActions.READ.id, ActionGroup.READ)
        put(CampaignActions.LIST.id, ActionGroup.READ)
        put(MemberActions.READ.id, ActionGroup.READ)
        put(MemberActions.LIST.id, ActionGroup.READ)

        // WRITE actions
        put(WorkspaceActions.UPDATE.id, ActionGroup.WRITE)
        put(CommunityActions.UPDATE.id, ActionGroup.WRITE)
        put(IdeaActions.CREATE.id, ActionGroup.WRITE)
        put(IdeaActions.EDIT.id, ActionGroup.WRITE)
        put(IdeaActions.DELETE.id, ActionGroup.WRITE)
        put(CampaignActions.CREATE.id, ActionGroup.WRITE)
        put(CampaignActions.UPDATE.id, ActionGroup.WRITE)
        put(CampaignActions.DELETE.id, ActionGroup.WRITE)
        put(MemberActions.UPDATE.id, ActionGroup.WRITE)

        // MODERATE actions
        put(IdeaActions.Moderate.HIDE.id, ActionGroup.MODERATE)
        put(IdeaActions.Moderate.UNHIDE.id, ActionGroup.MODERATE)
        put(IdeaActions.Moderate.LOCK.id, ActionGroup.MODERATE)
        put(IdeaActions.Moderate.UNLOCK.id, ActionGroup.MODERATE)

        // ADMIN actions
        put(MemberActions.BAN.id, ActionGroup.ADMIN)
        put(MemberActions.UNBAN.id, ActionGroup.ADMIN)
        put(MemberActions.INVITE.id, ActionGroup.ADMIN)
        put(CampaignActions.LAUNCH.id, ActionGroup.ADMIN)
        put(CampaignActions.CLOSE.id, ActionGroup.ADMIN)
        put(CampaignActions.ARCHIVE.id, ActionGroup.ADMIN)
    }

    fun groupOf(action: Action): ActionGroup =
        actionGroups[action.id] ?: ActionGroup.UNKNOWN

    // Backward-compatible helper methods
    fun isWrite(action: Action): Boolean =
        groupOf(action).let { it == ActionGroup.WRITE || it == ActionGroup.MODERATE }

    fun isModeration(action: Action): Boolean =
        groupOf(action) == ActionGroup.MODERATE

    fun isAdmin(action: Action): Boolean =
        groupOf(action) == ActionGroup.ADMIN
}
