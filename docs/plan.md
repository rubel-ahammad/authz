You are an AI coding agent. Create a NEW Kotlin/JVM library project from scratch (no existing repo). The project is a framework-neutral authorization contract library (PBAC/ReBAC foundation).

PROJECT IDENTITY
- Project (root directory) name: authz-core
- Gradle group: com.ideascale
- Artifact: authz-core
- Package root: com.ideascale.authz
- Build tool: Gradle Kotlin DSL
- Target: Java 17
- Keep dependencies minimal:
  - Kotlin stdlib
  - Tests: kotlin.test (use Gradle test task)
- Output must compile and pass tests via: ./gradlew test

DELIVERABLES
Create a complete project directory including:
- settings.gradle.kts
- build.gradle.kts
- gradle.properties (optional)
- README.md
- src/main/kotlin/... (all files below)
- src/test/kotlin/... (tests below)

IMPLEMENTATION (CREATE THESE FILES EXACTLY)

========================================
Gradle files
========================================

File: settings.gradle.kts
----------------------------------------
rootProject.name = "authz-core"

File: build.gradle.kts
----------------------------------------
plugins {
kotlin("jvm") version "2.0.21"
`java-library`
}

group = "com.ideascale"
version = "0.1.0"

java {
toolchain {
languageVersion.set(JavaLanguageVersion.of(17))
}
}

kotlin {
jvmToolchain(17)
}

repositories {
mavenCentral()
}

dependencies {
testImplementation(kotlin("test"))
}

tasks.test {
useJUnitPlatform()
}

Notes:
- If kotlin("test") requires JUnit, add minimal JUnit platform dependency ONLY if tests fail:
  testRuntimeOnly("org.junit.platform:junit-platform-launcher")
  Keep it minimal.

========================================
Main source files (package com.ideascale.authz)
========================================

File: src/main/kotlin/com/ideascale/authz/Action.kt
----------------------------------------
package com.ideascale.authz

/**
* Canonical action identifier (e.g., "idea.edit", "campaign.launch", "member.ban").
*
* NOTE: We intentionally do NOT enforce a strict regex at runtime.
* Enforce naming conventions via tests / lint / review instead.
  */
  @JvmInline
  value class Action(val id: String) {
  init {
  require(id.isNotBlank()) { "Action id cannot be blank" }
  }

override fun toString(): String = id
}

File: src/main/kotlin/com/ideascale/authz/ResourceType.kt
----------------------------------------
package com.ideascale.authz

/**
* Stable set of resource types used across microservices.
*
* Why enum?
* - Stable + discoverable
* - Plays well with Kotlin/JVM + JSON serialization
* - Prevents string drift ("Idea" vs "idea" vs "ideas")
*
* Evolve by ADDING new values; avoid renaming/removing to keep backward compatibility.
  */
  enum class ResourceType {
  WORKSPACE,
  COMMUNITY,
  CAMPAIGN,
  GROUP,
  IDEA,
  MEMBER,

// Optional: if you have a dedicated "subscription" entity
SUBSCRIPTION,

// Optional: common cross-cutting resources
TRANSLATION,
MODERATION_CASE
}

File: src/main/kotlin/com/ideascale/authz/ResourceRef.kt
----------------------------------------
package com.ideascale.authz

/**
* Reference to a protected resource.
*
* id: Use your canonical identifier for the resource (stringified UUID/Long/etc).
* workspaceId is carried in Subject (tenant boundary), not duplicated here.
  */
  data class ResourceRef(
  val type: ResourceType,
  val id: String
  ) {
  init {
  require(id.isNotBlank()) { "Resource id cannot be blank" }
  }
  }

File: src/main/kotlin/com/ideascale/authz/PrincipalType.kt
----------------------------------------
package com.ideascale.authz

enum class PrincipalType { USER, SERVICE }

File: src/main/kotlin/com/ideascale/authz/Subject.kt
----------------------------------------
package com.ideascale.authz

/**
* Subject of authorization.
*
* workspaceId: your tenant id boundary
* memberId: the effective subject (user)
* actorMemberId: set when impersonating ("admin acting as")
  */
  data class Subject(
  val workspaceId: String,
  val memberId: String,
  val principalType: PrincipalType = PrincipalType.USER,
  val actorMemberId: String? = null
  ) {
  init {
  require(workspaceId.isNotBlank()) { "workspaceId cannot be blank" }
  require(memberId.isNotBlank()) { "memberId cannot be blank" }
  require(actorMemberId?.isNotBlank() ?: true) { "actorMemberId cannot be blank" }
  }

val isImpersonating: Boolean get() = actorMemberId != null && actorMemberId != memberId
}

File: src/main/kotlin/com/ideascale/authz/Channel.kt
----------------------------------------
package com.ideascale.authz

/**
* Where the request originated (useful for IP restrictions, stricter admin routes, etc.).
  */
  enum class Channel {
  PUBLIC_API,
  ADMIN_UI,
  INTERNAL_JOB,
  INTERNAL_SERVICE
  }

File: src/main/kotlin/com/ideascale/authz/AuthzContext.kt
----------------------------------------
package com.ideascale.authz

/**
* Purpose-built context. Keep it typed and stable.
*
* attributes: reserved escape hatch for non-core signals; keep it small and documented.
  */
  data class AuthzContext(
  val requestId: String? = null,
  val ip: String? = null,
  val userAgent: String? = null,
  val channel: Channel = Channel.PUBLIC_API,
  val attributes: Map<String, String> = emptyMap()
  )

File: src/main/kotlin/com/ideascale/authz/Effect.kt
----------------------------------------
package com.ideascale.authz

enum class Effect { ALLOW, DENY }

File: src/main/kotlin/com/ideascale/authz/Obligation.kt
----------------------------------------
package com.ideascale.authz

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

File: src/main/kotlin/com/ideascale/authz/ReasonCode.kt
----------------------------------------
package com.ideascale.authz

/**
* Stable reason codes for audit/debug/support.
*
* Governance rules:
* - NEVER rename existing codes (treat as API)
* - Add new codes as needed
* - Codes are UPPER_SNAKE_CASE
* - Prefix with ALLOW_ or DENY_
    */
    @JvmInline
    value class ReasonCode(val value: String) {
    init {
    require(value.isNotBlank()) { "ReasonCode cannot be blank" }
    }

override fun toString(): String = value

companion object {
// Generic / framework-level
val DENY_DEFAULT = ReasonCode("DENY_DEFAULT")
val DENY_NOT_AUTHENTICATED = ReasonCode("DENY_NOT_AUTHENTICATED")
val DENY_TENANT_MISMATCH = ReasonCode("DENY_TENANT_MISMATCH")

    // Hard gates (ABAC-style global denies)
    val DENY_BANNED = ReasonCode("DENY_BANNED")
    val DENY_PENDING = ReasonCode("DENY_PENDING")
    val DENY_SUBSCRIPTION_BLOCKED = ReasonCode("DENY_SUBSCRIPTION_BLOCKED")
    val DENY_IP_RESTRICTED = ReasonCode("DENY_IP_RESTRICTED")
    val DENY_EMAIL_DOMAIN_BLOCKED = ReasonCode("DENY_EMAIL_DOMAIN_BLOCKED")
    val DENY_EMAIL_DOMAIN_NOT_ALLOWED = ReasonCode("DENY_EMAIL_DOMAIN_NOT_ALLOWED")

    // Scope/relationship
    val DENY_NOT_IN_SCOPE = ReasonCode("DENY_NOT_IN_SCOPE")
    val DENY_INSUFFICIENT_PRIVILEGE = ReasonCode("DENY_INSUFFICIENT_PRIVILEGE")

    // Resource state
    val DENY_RESOURCE_READONLY = ReasonCode("DENY_RESOURCE_READONLY")
    val DENY_CAMPAIGN_EXPIRED = ReasonCode("DENY_CAMPAIGN_EXPIRED")

    // Allows (generic)
    val ALLOW_ROLE = ReasonCode("ALLOW_ROLE")
    val ALLOW_OWNER = ReasonCode("ALLOW_OWNER")
    val ALLOW_RELATIONSHIP = ReasonCode("ALLOW_RELATIONSHIP")
    val ALLOW_SYSTEM = ReasonCode("ALLOW_SYSTEM")
}
}

File: src/main/kotlin/com/ideascale/authz/Decision.kt
----------------------------------------
package com.ideascale.authz

import java.util.UUID

/**
* Authorization decision.
*
* decisionId: lets you correlate logs across microservices.
* details: optional structured info (e.g., matchedRuleId, matchedGrant, policyVersion).
  */
  data class Decision(
  val effect: Effect,
  val reason: ReasonCode,
  val obligations: Set<Obligation> = emptySet(),
  val decisionId: String = UUID.randomUUID().toString(),
  val details: Map<String, String> = emptyMap()
  ) {
  val allowed: Boolean get() = effect == Effect.ALLOW

companion object {
fun allow(
reason: ReasonCode = ReasonCode.ALLOW_SYSTEM,
obligations: Set<Obligation> = emptySet(),
details: Map<String, String> = emptyMap()
): Decision = Decision(
effect = Effect.ALLOW,
reason = reason,
obligations = obligations,
details = details
)

    fun deny(
      reason: ReasonCode = ReasonCode.DENY_DEFAULT,
      details: Map<String, String> = emptyMap()
    ): Decision = Decision(
      effect = Effect.DENY,
      reason = reason,
      details = details
    )
}
}

File: src/main/kotlin/com/ideascale/authz/Authorizer.kt
----------------------------------------
package com.ideascale.authz

/**
* Transport-neutral authorization interface.
*
* Put framework-specific helpers (Spring/Ktor filters, exceptions, etc.)
* in separate modules (e.g., authz-spring, authz-ktor).
  */
  interface Authorizer {
  fun authorize(
  subject: Subject,
  action: Action,
  resource: ResourceRef,
  context: AuthzContext = AuthzContext()
  ): Decision
  }

File: src/main/kotlin/com/ideascale/authz/DecisionLogFields.kt
----------------------------------------
package com.ideascale.authz

/**
* Helps services log consistent fields without committing to a logging framework.
  */
  fun Decision.toLogFields(
  subject: Subject,
  action: Action,
  resource: ResourceRef,
  context: AuthzContext
  ): Map<String, String> = buildMap {
  put("workspaceId", subject.workspaceId)
  put("memberId", subject.memberId)
  put("principalType", subject.principalType.name)
  subject.actorMemberId?.let { put("actorMemberId", it) }

put("action", action.id)
put("resourceType", resource.type.name)
put("resourceId", resource.id)

put("effect", effect.name)
put("reason", reason.value)
put("decisionId", decisionId)

context.requestId?.let { put("requestId", it) }
context.ip?.let { put("ip", it) }
put("channel", context.channel.name)

// Include details last
details.forEach { (k, v) -> put("detail.$k", v) }
}

========================================
Action catalogs (package com.ideascale.authz.actions)
========================================

File: src/main/kotlin/com/ideascale/authz/actions/IdeaActions.kt
----------------------------------------
package com.ideascale.authz.actions

import com.ideascale.authz.Action

object IdeaActions {
val READ = Action("idea.read")
val LIST = Action("idea.list")
val CREATE = Action("idea.create")
val EDIT = Action("idea.edit")
val DELETE = Action("idea.delete")

object Moderate {
val HIDE = Action("idea.moderate.hide")
val UNHIDE = Action("idea.moderate.unhide")
val LOCK = Action("idea.moderate.lock")
val UNLOCK = Action("idea.moderate.unlock")
}
}

File: src/main/kotlin/com/ideascale/authz/actions/CampaignActions.kt
----------------------------------------
package com.ideascale.authz.actions

import com.ideascale.authz.Action

object CampaignActions {
val READ = Action("campaign.read")
val LIST = Action("campaign.list")
val CREATE = Action("campaign.create")
val UPDATE = Action("campaign.update")
val DELETE = Action("campaign.delete")

val LAUNCH = Action("campaign.launch")
val CLOSE = Action("campaign.close")
val ARCHIVE = Action("campaign.archive")
}

File: src/main/kotlin/com/ideascale/authz/actions/MemberActions.kt
----------------------------------------
package com.ideascale.authz.actions

import com.ideascale.authz.Action

object MemberActions {
val READ = Action("member.read")
val LIST = Action("member.list")
val UPDATE = Action("member.update")

val BAN = Action("member.ban")
val UNBAN = Action("member.unban")
val INVITE = Action("member.invite")
}

========================================
Tests (kotlin.test)
========================================

File: src/test/kotlin/com/ideascale/authz/ActionNamingConventionTest.kt
----------------------------------------
package com.ideascale.authz

import com.ideascale.authz.actions.CampaignActions
import com.ideascale.authz.actions.IdeaActions
import com.ideascale.authz.actions.MemberActions
import kotlin.test.Test
import kotlin.test.assertTrue

/**
* Naming conventions belong in tests (not runtime).
  */
  class ActionNamingConventionTest {

private val pattern = Regex("^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+\$")

@Test
fun `action ids follow convention`() {
val actions = listOf(
IdeaActions.READ, IdeaActions.LIST, IdeaActions.CREATE, IdeaActions.EDIT, IdeaActions.DELETE,
IdeaActions.Moderate.HIDE, IdeaActions.Moderate.UNHIDE, IdeaActions.Moderate.LOCK, IdeaActions.Moderate.UNLOCK,
CampaignActions.READ, CampaignActions.LIST, CampaignActions.CREATE, CampaignActions.UPDATE, CampaignActions.DELETE,
CampaignActions.LAUNCH, CampaignActions.CLOSE, CampaignActions.ARCHIVE,
MemberActions.READ, MemberActions.LIST, MemberActions.UPDATE, MemberActions.BAN, MemberActions.UNBAN, MemberActions.INVITE
)

    actions.forEach { a ->
      assertTrue(pattern.matches(a.id), "Invalid action id: ${a.id}")
    }
}
}

File: src/test/kotlin/com/ideascale/authz/ReasonCodeConventionTest.kt
----------------------------------------
package com.ideascale.authz

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

private val upperSnake = Regex("^[A-Z][A-Z0-9_]*\$")

@Test
fun `reason codes follow conventions`() {
val companion = ReasonCode::class.companionObjectInstance!!
val props = companion::class.memberProperties
.filter { it.returnType.classifier == ReasonCode::class }

    props.forEach { prop ->
      val rc = prop.getter.call(companion) as ReasonCode
      val v = rc.value
      assertTrue(upperSnake.matches(v), "Reason code not UPPER_SNAKE_CASE: $v")
      assertTrue(v.startsWith("ALLOW_") || v.startsWith("DENY_"), "Reason code must start with ALLOW_ or DENY_: $v")
    }
}
}

========================================
README
========================================

File: README.md
----------------------------------------
# authz-core

Framework-neutral Kotlin/JVM library that defines authorization contract types for PBAC/ReBAC-style authorization.

## What it provides
- Canonical `Action` identifiers (e.g., `idea.edit`, `campaign.launch`)
- Stable `ResourceType` + `ResourceRef`
- `Subject` (tenant = workspaceId, user = memberId, optional actorMemberId for impersonation)
- `AuthzContext` (request context signals)
- `Decision` with `Effect`, `ReasonCode`, and optional `Obligation`s
- `Authorizer` interface (transport-neutral)
- Logging helper: `Decision.toLogFields(...)`
- Example action catalogs and tests enforcing naming conventions

## Example usage
```kotlin
import com.ideascale.authz.*
import com.ideascale.authz.actions.IdeaActions

val subject = Subject(workspaceId = "w1", memberId = "m42")
val resource = ResourceRef(ResourceType.IDEA, id = "idea-123")
val ctx = AuthzContext(requestId = "req-1", ip = "10.0.0.1", channel = Channel.PUBLIC_API)

val authorizer: Authorizer = object : Authorizer {
  override fun authorize(subject: Subject, action: Action, resource: ResourceRef, context: AuthzContext): Decision {
    return Decision.deny(ReasonCode.DENY_DEFAULT)
  }
}

val decision = authorizer.authorize(subject, IdeaActions.EDIT, resource, ctx)
println(decision.allowed)
println(decision.toLogFields(subject, IdeaActions.EDIT, resource, ctx))
