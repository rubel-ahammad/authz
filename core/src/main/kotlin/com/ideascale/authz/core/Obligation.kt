package com.ideascale.authz.core

/**
 * Obligations are "things the caller must do" when a request is allowed,
 * e.g., require step-up auth or redact fields.
 *
 * Keep obligations small, enumerable, and well-documented.
 */
sealed interface Obligation {
    data object REQUIRE_STEP_UP_AUTH : Obligation
    data class REDACT_FIELDS(val fields: Set<String>) : Obligation
}
