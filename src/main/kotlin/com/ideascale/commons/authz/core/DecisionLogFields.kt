package com.ideascale.commons.authz.core

/**
 * Helps services log consistent fields without committing to a logging framework.
 */
fun Decision.toLogFields(
    subject: Subject,
    action: Action,
    resource: ResourceRef,
    context: AuthzContext
): Map<String, String> = buildMap {
    put("workspaceId", subject.workspaceId)
    put("memberId", subject.memberId)
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
