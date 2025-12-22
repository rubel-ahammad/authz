package com.ideascale.authz.engine.providers

import com.ideascale.authz.core.Channel

interface GlobalDenyProvider {
    fun isBanned(workspaceId: String, memberId: String): Boolean
    fun isPending(workspaceId: String, memberId: String): Boolean
    fun isSubscriptionBlocked(workspaceId: String): Boolean
    fun isIpAllowed(workspaceId: String, ip: String?, channel: Channel): Boolean

    fun isEmailDomainBlocked(workspaceId: String, email: String?): Boolean = false
    fun isEmailDomainAllowed(workspaceId: String, email: String?): Boolean = true
}
