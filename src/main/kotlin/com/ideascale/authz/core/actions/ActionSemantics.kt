package com.ideascale.authz.core.actions

import com.ideascale.authz.core.Action

object ActionSemantics {
    private val moderationActionIds: Set<String> = setOf(
        IdeaActions.Moderate.HIDE.id,
        IdeaActions.Moderate.UNHIDE.id,
        IdeaActions.Moderate.LOCK.id,
        IdeaActions.Moderate.UNLOCK.id
    )

    private val writeActionIds: Set<String> = setOf(
        IdeaActions.CREATE.id,
        IdeaActions.EDIT.id,
        IdeaActions.DELETE.id,
        CampaignActions.CREATE.id,
        CampaignActions.UPDATE.id,
        CampaignActions.DELETE.id,
        CampaignActions.LAUNCH.id,
        CampaignActions.CLOSE.id,
        CampaignActions.ARCHIVE.id,
        MemberActions.UPDATE.id,
        MemberActions.BAN.id,
        MemberActions.UNBAN.id,
        MemberActions.INVITE.id
    ) + moderationActionIds

    private val adminActionIds: Set<String> = setOf(
        MemberActions.BAN.id,
        MemberActions.UNBAN.id,
        MemberActions.INVITE.id,
        CampaignActions.LAUNCH.id,
        CampaignActions.CLOSE.id,
        CampaignActions.ARCHIVE.id
    )

    fun isWrite(action: Action): Boolean = action.id in writeActionIds

    fun isModeration(action: Action): Boolean = action.id in moderationActionIds

    fun isAdmin(action: Action): Boolean = action.id in adminActionIds
}