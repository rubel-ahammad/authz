package com.ideascale.authz.core.action

import com.ideascale.authz.core.Action

object IdeaActions {
    val READ = Action("idea.read")
    val LIST = Action("idea.list")
    val CREATE = Action("idea.create")
    val EDIT = Action("idea.edit")
    val DELETE = Action("idea.delete")

    object Moderate {
        val HIDE = Action("idea.moderate.hide")
        val UNHIDE = Action("idea.moderate.unhide")
        val LOCK = Action("idea.moderate.lock")
        val UNLOCK = Action("idea.moderate.unlock")
    }
}
