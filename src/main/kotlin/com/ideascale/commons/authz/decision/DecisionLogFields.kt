package com.ideascale.commons.authz.decision

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.AuthorizationContext
import com.ideascale.commons.authz.Principal
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
    put("workspaceId", principal.workspaceId)
    principal.memberId?.let { put("memberId", it) }
    put("principalType", principal.principalType.name)
    principal.actorMemberId?.let { put("actorMemberId", it) }

    put("action", action.id)
    put("resourceType", resource.type.name)
    put("resourceId", resource.id)

    put("effect", effect.name)
    put("reason", reason.value)
    put("decisionId", decisionId)

    context.requestId?.let { put("requestId", it) }
    context.ip?.let { put("ip", it) }
    put("channel", context.channel.name)

    // Include details last
    details.forEach { (k, v) -> put("detail.$k", v) }
}
