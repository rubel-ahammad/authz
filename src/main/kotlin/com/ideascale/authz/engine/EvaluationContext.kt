package com.ideascale.authz.engine

import com.ideascale.authz.core.Decision
import com.ideascale.authz.core.Obligation
import com.ideascale.authz.core.ReasonCode

class EvaluationContext(
    val request: AuthzRequest
) {
    var contextFacts: ResourceContext? = null
    var relationshipContext: RelationshipContext? = null
    var attributeContext: AttributeContext? = null
    var roleContext: RoleContext? = null

    private val memo: MutableMap<String, Any?> = mutableMapOf()

    @Suppress("UNCHECKED_CAST")
    fun <T> memoize(key: String, loader: () -> T): T {
        if (memo.containsKey(key)) {
            return memo[key] as T
        }
        val value = loader()
        memo[key] = value
        return value
    }

    fun deny(
        reason: ReasonCode,
        details: Map<String, String> = emptyMap()
    ): Decision = Decision.deny(
        reason = reason,
        details = baseDetails() + details
    )

    fun allow(
        reason: ReasonCode,
        obligations: Set<Obligation> = emptySet(),
        details: Map<String, String> = emptyMap()
    ): Decision = Decision.allow(
        reason = reason,
        obligations = obligations,
        details = baseDetails() + details
    )

    fun withBaseDetails(decision: Decision): Decision = decision.copy(
        details = baseDetails() + decision.details
    )

    private fun baseDetails(): Map<String, String> = buildMap {
        put("action", request.action.id)
        put("resourceType", request.resource.type.name)
        put("resourceId", request.resource.id)
        request.context.requestId?.let { put("requestId", it) }
    }
}
