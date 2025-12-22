package com.ideascale.authz.engine.policies

import com.ideascale.authz.core.Action
import com.ideascale.authz.core.Decision
import com.ideascale.authz.core.ResourceRef
import com.ideascale.authz.engine.Authorities
import com.ideascale.authz.engine.RelationshipFacts
import com.ideascale.authz.engine.ResourceContext

interface AuthorityPolicy {
    fun allowDecisionIfMatched(
        action: Action,
        resource: ResourceRef,
        rc: ResourceContext,
        rf: RelationshipFacts,
        authorities: Authorities
    ): Decision?
}
