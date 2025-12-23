package com.ideascale.authz.core.action

import com.ideascale.authz.core.Action

object MemberActions {
    val READ = Action("member.read")
    val LIST = Action("member.list")
    val UPDATE = Action("member.update")

    val BAN = Action("member.ban")
    val UNBAN = Action("member.unban")
    val INVITE = Action("member.invite")
}
