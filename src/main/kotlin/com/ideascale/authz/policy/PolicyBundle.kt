package com.ideascale.authz.policy

import com.ideascale.authz.policy.catalog.GlobalRules
import com.ideascale.authz.policy.catalog.IdeaRules
import com.ideascale.authz.policy.rule.AllowRule
import com.ideascale.authz.policy.rule.DenyRule
import com.ideascale.authz.policy.rule.RuleRegistry

data class StageRuleRegistries(
    val resourceContext: RuleRegistry,
    val relationship: RuleRegistry,
    val attribute: RuleRegistry,
    val role: RuleRegistry
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

    fun roleRules(): List<AllowRule> = buildList {
        addAll(IdeaRules.roleAllowRules())
    }

    fun registries(): StageRuleRegistries = StageRuleRegistries(
        resourceContext = RuleRegistry(resourceContextRules(), emptyList()),
        relationship = RuleRegistry(relationshipRules(), emptyList()),
        attribute = RuleRegistry(attributeRules(), emptyList()),
        role = RuleRegistry(emptyList(), roleRules())
    )
}
