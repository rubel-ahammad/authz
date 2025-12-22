package com.ideascale.authz.core

/**
 * Canonical action identifier (e.g., "idea.edit", "campaign.launch", "member.ban").
 *
 * NOTE: We intentionally do NOT enforce a strict regex at runtime.
 * Enforce naming conventions via tests / lint / review instead.
 */
@JvmInline
value class Action(val id: String) {
    init {
        require(id.isNotBlank()) { "Action id cannot be blank" }
    }

    override fun toString(): String = id
}
