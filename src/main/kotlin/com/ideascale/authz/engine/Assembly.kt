package com.ideascale.authz.engine

import com.ideascale.authz.core.Authorizer
import com.ideascale.authz.engine.evaluator.AttributeEvaluationStep
import com.ideascale.authz.engine.evaluator.RoleEvaluationStep
import com.ideascale.authz.engine.evaluator.RelationshipEvaluationStep
import com.ideascale.authz.engine.evaluator.ResourceEvaluationStep
import com.ideascale.authz.context.provider.AttributeContextProvider
import com.ideascale.authz.context.provider.RelationshipContextProvider
import com.ideascale.authz.context.provider.ResourceContextProvider
import com.ideascale.authz.context.provider.RoleContextProvider
import com.ideascale.authz.policy.DefaultPolicyBundle
import com.ideascale.authz.policy.StageRuleRegistries
import com.ideascale.authz.policy.rule.ActionClassifier
import com.ideascale.authz.policy.rule.DefaultActionClassifier

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
