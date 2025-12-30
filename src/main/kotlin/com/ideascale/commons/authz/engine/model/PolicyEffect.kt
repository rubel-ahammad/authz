package com.ideascale.commons.authz.engine.model

/**
 * Cedar policy effect - either permit or forbid.
 *
 * - PERMIT: Policy grants access if scope and conditions match
 * - FORBID: Policy explicitly denies access if scope and conditions match
 *
 * Cedar evaluation semantics: FORBID always overrides PERMIT.
 */
enum class PolicyEffect {
    PERMIT,
    FORBID
}
