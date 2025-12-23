package com.ideascale.authz.engine.policies

import com.ideascale.authz.engine.policies.rules.GlobalRules
import com.ideascale.authz.engine.policies.rules.IdeaRules
import com.ideascale.authz.engine.rules.AllowRule
import com.ideascale.authz.engine.rules.DenyRule
import com.ideascale.authz.engine.rules.RuleRegistry

data class StageRuleRegistries(
    val resourceContext: RuleRegistry,
    val relationship: RuleRegistry,
    val attribute: RuleRegistry,
    val authority: RuleRegistry
)

object DefaultPolicyBundle {
    fun resourceContextRules(): List<DenyRule> = buildList {
        addAll(IdeaRules.resourceContextDenyRules())
    }

    fun relationshipRules(): List<DenyRule> = buildList {
        addAll(IdeaRules.relationshipDenyRules())
    }

    fun attributeRules(): List<DenyRule> = buildList {
        addAll(GlobalRules.attributeDenyRules())
        addAll(IdeaRules.attributeDenyRules())
    }

    fun authorityRules(): List<AllowRule> = buildList {
        addAll(IdeaRules.authorityAllowRules())
    }

    fun registries(): StageRuleRegistries = StageRuleRegistries(
        resourceContext = RuleRegistry(resourceContextRules(), emptyList()),
        relationship = RuleRegistry(relationshipRules(), emptyList()),
        attribute = RuleRegistry(attributeRules(), emptyList()),
        authority = RuleRegistry(emptyList(), authorityRules())
    )
}
