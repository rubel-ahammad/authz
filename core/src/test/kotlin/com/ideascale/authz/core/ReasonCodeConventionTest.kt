package com.ideascale.authz.core

import kotlin.reflect.full.companionObjectInstance
import kotlin.reflect.full.memberProperties
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Guards reason code governance at compile-time:
 * - must be UPPER_SNAKE_CASE
 * - must start with ALLOW_ or DENY_
 */
class ReasonCodeConventionTest {

    private val upperSnake = Regex("^[A-Z][A-Z0-9_]*$")

    @Test
    fun `reason codes follow conventions`() {
        val companion = ReasonCode::class.companionObjectInstance!!
        val props = companion::class.memberProperties
            .filter { it.returnType.classifier == ReasonCode::class }

        props.forEach { prop ->
            val rc = prop.getter.call(companion) as ReasonCode
            val v = rc.value
            assertTrue(upperSnake.matches(v), "Reason code not UPPER_SNAKE_CASE: $v")
            assertTrue(
                v.startsWith("ALLOW_") || v.startsWith("DENY_"),
                "Reason code must start with ALLOW_ or DENY_: $v"
            )
        }
    }
}
