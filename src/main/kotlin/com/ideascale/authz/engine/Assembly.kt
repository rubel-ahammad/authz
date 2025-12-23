package com.ideascale.authz.engine

import com.ideascale.authz.core.Authorizer
import com.ideascale.authz.engine.evaluators.AttributeEvaluationStep
import com.ideascale.authz.engine.evaluators.RoleEvaluationStep
import com.ideascale.authz.engine.evaluators.RelationshipEvaluationStep
import com.ideascale.authz.engine.evaluators.ResourceContextEvaluationStep
import com.ideascale.authz.engine.policies.DefaultPolicyBundle
import com.ideascale.authz.engine.policies.StageRuleRegistries
import com.ideascale.authz.engine.providers.AttributeProvider
import com.ideascale.authz.engine.providers.RoleProvider
import com.ideascale.authz.engine.providers.RelationshipProvider
import com.ideascale.authz.engine.providers.ResourceContextProvider
import com.ideascale.authz.engine.rules.ActionClassifier
import com.ideascale.authz.engine.rules.DefaultActionClassifier

data class PipelineDependencies(
    val resourceContextProvider: ResourceContextProvider,
    val relationshipProvider: RelationshipProvider,
    val attributeProvider: AttributeProvider,
    val roleProvider: RoleProvider,
    val ruleRegistries: StageRuleRegistries = DefaultPolicyBundle.registries(),
    val actionClassifier: ActionClassifier = DefaultActionClassifier
)

object PipelineAuthorizerFactory {
    fun build(deps: PipelineDependencies): Authorizer {
        val registries = deps.ruleRegistries
        val classifier = deps.actionClassifier

        val steps = listOf(
            ResourceContextEvaluationStep(deps.resourceContextProvider, registries.resourceContext, classifier),
            RelationshipEvaluationStep(deps.relationshipProvider, registries.relationship, classifier),
            AttributeEvaluationStep(deps.attributeProvider, registries.attribute, classifier),
            RoleEvaluationStep(deps.roleProvider, registries.role, classifier)
        )

        return PipelineAuthorizer(steps)
    }
}
