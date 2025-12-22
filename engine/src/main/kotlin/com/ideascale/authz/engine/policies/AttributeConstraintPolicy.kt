package com.ideascale.authz.engine.policies

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.ReasonCode
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.AttributeFacts
import com.ideascale.authz.engine.RelationshipFacts
import com.ideascale.authz.engine.ResourceContext

interface AttributeConstraintPolicy {
    fun denyReasonIfForbidden(
        action: Action,
        resource: ResourceRef,
        rc: ResourceContext,
        rf: RelationshipFacts,
        af: AttributeFacts
    ): ReasonCode?
}
