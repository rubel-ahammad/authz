package com.ideascale.commons.authz.context

data class RelationshipContext(
    val isIdeaOwner: Boolean = false,
    val viaGroupIds: Set<String> = emptySet()
)
