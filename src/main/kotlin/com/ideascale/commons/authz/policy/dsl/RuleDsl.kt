package com.ideascale.commons.authz.policy.dsl

import com.ideascale.commons.authz.core.ActionGroup
import com.ideascale.commons.authz.core.Decision
import com.ideascale.commons.authz.core.ReasonCode
import com.ideascale.commons.authz.core.ResourceType
import com.ideascale.commons.authz.engine.EvaluationContext
import com.ideascale.commons.authz.policy.rule.AllowRule
import com.ideascale.commons.authz.policy.rule.DenyRule
import com.ideascale.commons.authz.policy.rule.Target

fun deny(init: DenyRuleBuilder.() -> Unit): DenyRule =
    DenyRuleBuilder().apply(init).build()

fun deny(
    id: String,
    target: Target,
    evaluate: (EvaluationContext) -> ReasonCode?
): DenyRule = DenyRule(id = id, target = target, evaluate = evaluate)

fun deny(
    id: String,
    resourceType: ResourceType,
    actionGroup: ActionGroup,
    evaluate: (EvaluationContext) -> ReasonCode?
): DenyRule = DenyRule(id = id, target = Target(resourceType, actionGroup), evaluate = evaluate)

fun denyGlobal(
    id: String,
    actionGroup: ActionGroup,
    evaluate: (EvaluationContext) -> ReasonCode?
): DenyRule = DenyRule(id = id, target = Target.global(actionGroup), evaluate = evaluate)

fun allow(init: AllowRuleBuilder.() -> Unit): AllowRule =
    AllowRuleBuilder().apply(init).build()

fun allow(
    id: String,
    target: Target,
    evaluate: (EvaluationContext) -> Decision?
): AllowRule = AllowRule(id = id, target = target, evaluate = evaluate)

fun allow(
    id: String,
    resourceType: ResourceType,
    actionGroup: ActionGroup,
    evaluate: (EvaluationContext) -> Decision?
): AllowRule = AllowRule(id = id, target = Target(resourceType, actionGroup), evaluate = evaluate)

fun allowGlobal(
    id: String,
    actionGroup: ActionGroup,
    evaluate: (EvaluationContext) -> Decision?
): AllowRule = AllowRule(id = id, target = Target.global(actionGroup), evaluate = evaluate)

class DenyRuleBuilder {
    private var id: String? = null
    private var target: Target? = null
    private var evaluate: ((EvaluationContext) -> ReasonCode?)? = null

    fun id(value: String) {
        id = value
    }

    fun target(value: Target) {
        target = value
    }

    fun target(resourceType: ResourceType, actionGroup: ActionGroup) {
        target = Target(resourceType, actionGroup)
    }

    fun global(actionGroup: ActionGroup) {
        target = Target.global(actionGroup)
    }

    fun condition(block: (EvaluationContext) -> ReasonCode?) {
        evaluate = block
    }

    fun `when`(block: (EvaluationContext) -> ReasonCode?) {
        evaluate = block
    }

    fun build(): DenyRule = DenyRule(
        id = requireNotNull(id) { "deny rule requires id" },
        target = requireNotNull(target) { "deny rule requires target" },
        evaluate = requireNotNull(evaluate) { "deny rule requires condition" }
    )
}

class AllowRuleBuilder {
    private var id: String? = null
    private var target: Target? = null
    private var evaluate: ((EvaluationContext) -> Decision?)? = null

    fun id(value: String) {
        id = value
    }

    fun target(value: Target) {
        target = value
    }

    fun target(resourceType: ResourceType, actionGroup: ActionGroup) {
        target = Target(resourceType, actionGroup)
    }

    fun global(actionGroup: ActionGroup) {
        target = Target.global(actionGroup)
    }

    fun condition(block: (EvaluationContext) -> Decision?) {
        evaluate = block
    }

    fun `when`(block: (EvaluationContext) -> Decision?) {
        evaluate = block
    }

    fun build(): AllowRule = AllowRule(
        id = requireNotNull(id) { "allow rule requires id" },
        target = requireNotNull(target) { "allow rule requires target" },
        evaluate = requireNotNull(evaluate) { "allow rule requires condition" }
    )
}
