package com.ideascale.authz.engine

import com.ideascale.authz.core.Authorizer
import com.ideascale.authz.engine.evaluators.AttributeEvaluationStep
import com.ideascale.authz.engine.evaluators.RoleEvaluationStep
import com.ideascale.authz.engine.evaluators.RelationshipEvaluationStep
import com.ideascale.authz.engine.evaluators.ResourceEvaluationStep
import com.ideascale.authz.engine.policies.DefaultPolicyBundle
import com.ideascale.authz.engine.policies.StageRuleRegistries
import com.ideascale.authz.engine.providers.AttributeContextProvider
import com.ideascale.authz.engine.providers.RoleContextProvider
import com.ideascale.authz.engine.providers.RelationshipContextProvider
import com.ideascale.authz.engine.providers.ResourceContextProvider
import com.ideascale.authz.engine.rules.ActionClassifier
import com.ideascale.authz.engine.rules.DefaultActionClassifier

data class PipelineDependencies(
    val resourceContextProvider: ResourceContextProvider,
    val relationshipContextProvider: RelationshipContextProvider,
    val attributeContextProvider: AttributeContextProvider,
    val roleContextProvider: RoleContextProvider,
    val ruleRegistries: StageRuleRegistries = DefaultPolicyBundle.registries(),
    val actionClassifier: ActionClassifier = DefaultActionClassifier
)

object PipelineAuthorizerFactory {
    fun build(deps: PipelineDependencies): Authorizer {
        val registries = deps.ruleRegistries
        val classifier = deps.actionClassifier

        val steps = listOf(
            ResourceEvaluationStep(deps.resourceContextProvider, registries.resourceContext, classifier),
            RelationshipEvaluationStep(deps.relationshipContextProvider, registries.relationship, classifier),
            AttributeEvaluationStep(deps.attributeContextProvider, registries.attribute, classifier),
            RoleEvaluationStep(deps.roleContextProvider, registries.role, classifier)
        )

        return PipelineAuthorizer(steps)
    }
}
