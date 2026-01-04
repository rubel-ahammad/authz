package com.ideascale.commons.authz.decision

import com.ideascale.commons.authz.AuthorizationContext
import com.ideascale.commons.authz.Principal
import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.resource.Resource

/**
 * Helps services log consistent fields without committing to a logging framework.
 */
fun Decision.toLogFields(
    principal: Principal,
    action: Action,
    resource: Resource,
    context: AuthorizationContext
): Map<String, String> = buildMap {
    put("workspaceId", principal.workspaceId.toString())
    principal.id?.let { put("memberId", it.toString()) }
    put("principalType", principal.type.name)
    principal.actorId?.let { put("actorMemberId", it.toString()) }

    put("action", action.name)
    put("resourceType", resource.name)
    context.resource?.id?.let { put("resourceId", it.toString()) }

    put("effect", effect.name)
    put("reason", reason.value)
    put("decisionId", decisionId)

    put("requestId", context.environment.requestId)
    context.environment.ip?.let { put("ip", it) }
    put("channel", context.environment.channel.name)

    // Include details last
    details.forEach { (k, v) -> put("detail.$k", v) }
}
