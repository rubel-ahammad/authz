package com.ideascale.commons.authz.decision

import com.ideascale.commons.authz.action.Action
import com.ideascale.commons.authz.AuthorizationContext
import com.ideascale.commons.authz.Subject
import com.ideascale.commons.authz.resource.ResourceRef

/**
 * Helps services log consistent fields without committing to a logging framework.
 */
fun Decision.toLogFields(
    subject: Subject,
    action: Action,
    resource: ResourceRef,
    context: AuthorizationContext
): Map<String, String> = buildMap {
    put("workspaceId", subject.workspaceId)
    subject.memberId?.let { put("memberId", it) }
    put("principalType", subject.principalType.name)
    subject.actorMemberId?.let { put("actorMemberId", it) }

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
