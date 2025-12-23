package com.ideascale.authz.engine

import com.ideascale.authz.core.Authorizer
import com.ideascale.authz.engine.evaluators.AttributeConstraintEvaluator
import com.ideascale.authz.engine.evaluators.AuthorityEvaluator
import com.ideascale.authz.engine.evaluators.RelationshipEvaluator
import com.ideascale.authz.engine.evaluators.ResourceContextEvaluator
import com.ideascale.authz.engine.policies.DefaultPolicyBundle
import com.ideascale.authz.engine.policies.StageRuleRegistries
import com.ideascale.authz.engine.providers.AttributeProvider
import com.ideascale.authz.engine.providers.AuthorityProvider
import com.ideascale.authz.engine.providers.RelationshipProvider
import com.ideascale.authz.engine.providers.ResourceContextResolver
import com.ideascale.authz.engine.rules.ActionClassifier
import com.ideascale.authz.engine.rules.DefaultActionClassifier

data class PipelineDependencies(
    val resourceContextResolver: ResourceContextResolver,
    val relationshipProvider: RelationshipProvider,
    val attributeProvider: AttributeProvider,
    val authorityProvider: AuthorityProvider,
    val ruleRegistries: StageRuleRegistries = DefaultPolicyBundle.registries(),
    val actionClassifier: ActionClassifier = DefaultActionClassifier
)

object PipelineAuthorizerFactory {
    fun build(deps: PipelineDependencies): Authorizer {
        val registries = deps.ruleRegistries
        val classifier = deps.actionClassifier

        val evaluators = listOf(
            ResourceContextEvaluator(deps.resourceContextResolver, registries.resourceContext, classifier),
            RelationshipEvaluator(deps.relationshipProvider, registries.relationship, classifier),
            AttributeConstraintEvaluator(deps.attributeProvider, registries.attribute, classifier),
            AuthorityEvaluator(deps.authorityProvider, registries.authority, classifier)
        )

        return PipelineAuthorizer(evaluators)
    }
}
