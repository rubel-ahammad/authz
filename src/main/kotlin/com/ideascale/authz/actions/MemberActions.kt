package com.ideascale.authz.actions

import com.ideascale.authz.Action

object MemberActions {
    val READ = Action("member.read")
    val LIST = Action("member.list")
    val UPDATE = Action("member.update")

    val BAN = Action("member.ban")
    val UNBAN = Action("member.unban")
    val INVITE = Action("member.invite")
}
