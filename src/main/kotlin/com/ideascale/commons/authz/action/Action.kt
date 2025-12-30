package com.ideascale.commons.authz.action

/**
 * Canonical action identifier (e.g., "idea.edit", "campaign.launch", "member.ban").
 *
 * Implements [ActionItem] to participate in hierarchical action groups.
 *
 * NOTE: We intentionally do NOT enforce a strict regex at runtime.
 * Enforce naming conventions via tests / lint / review instead.
 */
@JvmInline
value class Action(override val id: String) : ActionItem {
    init {
        require(id.isNotBlank()) { "Action id cannot be blank" }
    }

    override fun toString(): String = id
}
