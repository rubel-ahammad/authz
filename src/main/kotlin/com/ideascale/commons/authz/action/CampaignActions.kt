package com.ideascale.commons.authz.action

import com.ideascale.commons.authz.action.Action

object CampaignActions {
    val READ = Action("campaign.read")
    val LIST = Action("campaign.list")
    val CREATE = Action("campaign.create")
    val UPDATE = Action("campaign.update")
    val DELETE = Action("campaign.delete")

    val LAUNCH = Action("campaign.launch")
    val CLOSE = Action("campaign.close")
    val ARCHIVE = Action("campaign.archive")
}
