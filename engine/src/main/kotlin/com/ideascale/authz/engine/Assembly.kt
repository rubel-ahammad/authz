package com.ideascale.authz.engine

import com.ideascale.authz.core.Authorizer
import com.ideascale.authz.engine.evaluators.AttributeConstraintEvaluator
import com.ideascale.authz.engine.evaluators.AuthorityEvaluator
import com.ideascale.authz.engine.evaluators.GlobalDenyEvaluator
import com.ideascale.authz.engine.evaluators.RelationshipEvaluator
import com.ideascale.authz.engine.evaluators.ResourceContextEvaluator
import com.ideascale.authz.engine.policies.AttributeConstraintPolicy
import com.ideascale.authz.engine.policies.AuthorityPolicy
import com.ideascale.authz.engine.policies.DefaultAttributeConstraintPolicy
import com.ideascale.authz.engine.policies.DefaultAuthorityPolicy
import com.ideascale.authz.engine.providers.AttributeProvider
import com.ideascale.authz.engine.providers.AuthorityProvider
import com.ideascale.authz.engine.providers.GlobalDenyProvider
import com.ideascale.authz.engine.providers.RelationshipProvider
import com.ideascale.authz.engine.providers.ResourceContextResolver

data class PipelineDependencies(
    val globalDenyProvider: GlobalDenyProvider,
    val resourceContextResolver: ResourceContextResolver,
    val relationshipProvider: RelationshipProvider,
    val attributeProvider: AttributeProvider,
    val authorityProvider: AuthorityProvider,
    val attributeConstraintPolicy: AttributeConstraintPolicy = DefaultAttributeConstraintPolicy(),
    val authorityPolicy: AuthorityPolicy = DefaultAuthorityPolicy()
)

fun buildDefaultPipelineAuthorizer(deps: PipelineDependencies): Authorizer {
    val evaluators = listOf(
        GlobalDenyEvaluator(deps.globalDenyProvider),
        ResourceContextEvaluator(deps.resourceContextResolver),
        RelationshipEvaluator(deps.relationshipProvider),
        AttributeConstraintEvaluator(deps.attributeProvider, deps.attributeConstraintPolicy),
        AuthorityEvaluator(deps.authorityProvider, deps.authorityPolicy)
    )

    return PipelineAuthorizer(evaluators)
}
