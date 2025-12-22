package com.ideascale.authz.core

import com.ideascale.authz.core.actions.CampaignActions
import com.ideascale.authz.core.actions.IdeaActions
import com.ideascale.authz.core.actions.MemberActions
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Naming conventions belong in tests (not runtime).
 */
class ActionNamingConventionTest {

    private val pattern = Regex("^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$")

    @Test
    fun `action ids follow convention`() {
        val actions = listOf(
            IdeaActions.READ,
            IdeaActions.LIST,
            IdeaActions.CREATE,
            IdeaActions.EDIT,
            IdeaActions.DELETE,
            IdeaActions.Moderate.HIDE,
            IdeaActions.Moderate.UNHIDE,
            IdeaActions.Moderate.LOCK,
            IdeaActions.Moderate.UNLOCK,
            CampaignActions.READ,
            CampaignActions.LIST,
            CampaignActions.CREATE,
            CampaignActions.UPDATE,
            CampaignActions.DELETE,
            CampaignActions.LAUNCH,
            CampaignActions.CLOSE,
            CampaignActions.ARCHIVE,
            MemberActions.READ,
            MemberActions.LIST,
            MemberActions.UPDATE,
            MemberActions.BAN,
            MemberActions.UNBAN,
            MemberActions.INVITE
        )

        actions.forEach { a ->
            assertTrue(pattern.matches(a.id), "Invalid action id: ${a.id}")
        }
    }
}
