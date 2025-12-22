package com.ideascale.authz.engine

import com.ideascale.authz.core.Channel
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.providers.AttributeProvider
import com.ideascale.authz.engine.providers.AuthorityProvider
import com.ideascale.authz.engine.providers.GlobalDenyProvider
import com.ideascale.authz.engine.providers.RelationshipProvider
import com.ideascale.authz.engine.providers.ResourceContextResolver

class RecordingGlobalDenyProvider(
    private val calls: MutableList<String>,
    private val banned: Boolean = false,
    private val pending: Boolean = false,
    private val subscriptionBlocked: Boolean = false,
    private val ipAllowed: Boolean = true
) : GlobalDenyProvider {
    private var recorded = false

    private fun record() {
        if (!recorded) {
            calls.add("GlobalDeny")
            recorded = true
        }
    }

    override fun isBanned(workspaceId: String, memberId: String): Boolean {
        record()
        return banned
    }

    override fun isPending(workspaceId: String, memberId: String): Boolean {
        record()
        return pending
    }

    override fun isSubscriptionBlocked(workspaceId: String): Boolean {
        record()
        return subscriptionBlocked
    }

    override fun isIpAllowed(workspaceId: String, ip: String?, channel: Channel): Boolean {
        record()
        return ipAllowed
    }
}

class RecordingResourceContextResolver(
    private val calls: MutableList<String>,
    private val rc: ResourceContext
) : ResourceContextResolver {
    override fun resolve(resource: ResourceRef): ResourceContext {
        calls.add("ResourceContext")
        return rc
    }
}

class RecordingRelationshipProvider(
    private val calls: MutableList<String>,
    private val rf: RelationshipFacts
) : RelationshipProvider {
    override fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        rc: ResourceContext
    ): RelationshipFacts {
        calls.add("Relationship")
        return rf
    }
}

class RecordingAttributeProvider(
    private val calls: MutableList<String>,
    private val af: AttributeFacts
) : AttributeProvider {
    override fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        rc: ResourceContext
    ): AttributeFacts {
        calls.add("Attribute")
        return af
    }
}

class RecordingAuthorityProvider(
    private val calls: MutableList<String>,
    private val authorities: Authorities
) : AuthorityProvider {
    override fun load(
        workspaceId: String,
        memberId: String,
        resource: ResourceRef,
        rc: ResourceContext,
        rf: RelationshipFacts
    ): Authorities {
        calls.add("Authority")
        return authorities
    }
}
