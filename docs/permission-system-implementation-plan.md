# Permission System Implementation Plan (Multi-tenant SaaS + Microservices)

This plan defines a credible, layered architecture for implementing permissions using:
- **PBAC** (policy-based orchestration)
- **ReBAC** (relationship/ownership/membership checks)
- **ABAC** (status/state/context gates)
- **RBAC** (scoped roles)

The goal is **correctness**, **consistency**, **explainability**, and **incremental adoption**.

---

## 1) Goals

1. **Correctness**
    - Prevent cross-workspace (tenant) data leaks.
    - Enforce bans / readonly / state constraints everywhere.
2. **Consistency**
    - Same action IDs, precedence, and evaluation order across all services.
3. **Explainability**
    - Every decision returns a `Decision` with `reasonCode` + `decisionId`.
4. **Incremental adoption**
    - Migrate endpoint-by-endpoint without rewriting the whole system.

---

## 2) Standardize Core Concepts

### 2.1 Canonical Action IDs
Every protected operation maps to a canonical action string:
- `idea.read`, `idea.list`, `idea.create`, `idea.edit`, `idea.delete`
- `idea.moderate.hide`, `campaign.launch`, `member.ban`, `role.assign`

**Rule:** Every endpoint/service method must call:
`authorize(subject, action, resourceRef, context)`

### 2.2 Scope hierarchy
Define and document the resource hierarchy (example):
- Workspace → Community → Campaign → Group → Idea

**Rule:** Code must be able to resolve a `ResourceRef` to its scope chain, at minimum to `workspaceId`.

---

## 3) Policy Laws (Evaluation Order)

Adopt this evaluation order everywhere:

1) **Authenticate & tenant bind**
2) **Global gates (hard denies)**
3) **Scope resolution & eligibility (membership / assignment)**
4) **Resource state constraints**
5) **Allow rules (RBAC + ReBAC + conditional ABAC)**
6) **Default deny**
7) **Return decision with reason code + decision id**

**Conventions**
- **Default deny**
- **Hard denies override allows**
- Deterministic reason code for every decision

---

## 4) Architecture Components

### A) PEP — Policy Enforcement Point (Per Service)
**What it is:** The place where requests are blocked or allowed.

**Where to enforce**
- Prefer **service layer** (domain service methods), not only controllers.
- Controllers call services; services enforce authorization.

**Developer requirements**
- Every mutation endpoint should have exactly one enforcement call near the top of the service method.
- List/search endpoints must enforce both:
    - **Action permission**
    - **Data visibility filtering**

**Expected interface**
- `Decision authorize(subject, action, resourceRef, context)`
- If denied: return/throw 403 (or gRPC PERMISSION_DENIED), and log reason + decisionId.

---

### B) PDP — Policy Decision Pipeline (Inside Each Service or Central Library)
**What it is:** A consistent pipeline that evaluates layered rules.

Implement it as a sequence of evaluators. Each evaluator may:
- return a final `Decision` (ALLOW/DENY), or
- continue to the next layer.

---

## 5) PDP Layers (What to Implement)

### Layer 0 — Identity & Tenant Binding
**Purpose**
- Ensure requests are tied to the correct workspace tenant and identity is known.

**Implement**
- Build `Subject(workspaceId, memberId, principalType, actorMemberId?)` from auth token.
- Build `AuthzContext(requestId, ip, channel, userAgent, attributes)`.
- Ensure `workspaceId` exists for non-public requests.
- Prevent IDOR: do not fetch resources without tenant scoping.

**Reason codes**
- `DENY_NOT_AUTHENTICATED`
- `DENY_TENANT_MISMATCH`

---

### Layer 1 — Global Gates (ABAC Hard Denies)
**Purpose**
- Apply universal “stop-the-world” rules early.

**Typical gates (based on our domain)**
- Member status: `BANNED`, `PENDING`, `MEMBER`
- Subscription: `ACTIVE`, `BLOCKED`, `SOFT_BLOCKED`
- IP restrictions (often stricter for admin channel)
- Email domain allow list / block list (registration/invites/admin access as defined)

**Implement**
- `GateService` providing:
    - member status
    - subscription state
    - ip allowed check
    - email domain checks (where relevant)

**Reason codes**
- `DENY_BANNED`, `DENY_PENDING`
- `DENY_SUBSCRIPTION_BLOCKED`
- `DENY_IP_RESTRICTED`
- `DENY_EMAIL_DOMAIN_BLOCKED`
- `DENY_EMAIL_DOMAIN_NOT_ALLOWED`

**Rules**
- These denies override any role/ownership.
- Keep these checks cheap and globally consistent.

---

### Layer 2 — Scope Resolution & Eligibility (ReBAC Membership / Assignment)
**Purpose**
- Determine the scope chain and confirm the subject is eligible for the scope.

**Implement**
1) `ResourceResolver` that maps `ResourceRef(type,id)` to:
    - `workspaceId`
    - optional `communityId`, `campaignId`, `groupId`
2) `EligibilityService` that answers:
    - is subject a member of workspace/community/campaign/group (as applicable)
    - is subject assigned moderator/admin of the relevant scope
    - is the resource public-readable (if applicable)

**Reason codes**
- `DENY_NOT_IN_SCOPE`

**Rules**
- Document and encode membership semantics:
    - Can a user be campaign moderator without community membership?
    - Is membership inherited (workspace → community → campaign)?

---

### Layer 3 — Resource State Constraints (ABAC State Machines)
**Purpose**
- Block actions when resources are in states that disallow them.

**Typical states**
- Campaign: `LAUNCHED`, `EXPIRED`, `READONLY`
- Member: `PENDING`
- Subscription: `SOFT_BLOCKED` (often treat as read-only for writes)
- Idea: locked/archived (if applicable)

**Implement**
- `StateService` to fetch states relevant to resource + parents (e.g., idea → campaign).
- `StatePolicy` mapping `(action, state)` to allow/deny.

**Reason codes**
- `DENY_RESOURCE_READONLY`
- `DENY_CAMPAIGN_EXPIRED`

**Rules to decide explicitly**
- Do admins bypass READONLY for content writes? (usually no)
- Are moderation actions allowed in READONLY? (often yes)
- Encode exceptions explicitly, not as ad-hoc checks.

---

### Layer 4 — Allow Rules (RBAC + ReBAC + Conditional ABAC)
**Purpose**
- Decide if the subject has sufficient privilege to perform the action.

**Inputs**
- Scoped roles:
    - Workspace Admin, Community Admin, Campaign Admin, Moderators, Specialist Moderators, etc.
- Relationships:
    - Owner of Idea, assigned moderator, group membership grants
- Attributes:
    - subscription ACTIVE, feature flags, etc.

**Implement**
- `GrantService` that returns effective grants in scope:
    - direct roles
    - roles via group membership (if applicable)
    - derived relations (owner → edit-own actions)
- `PermissionMapping` mapping roles/functions to allowed actions (or bundles).

**Reason codes**
- `ALLOW_ROLE`
- `ALLOW_OWNER`
- `ALLOW_RELATIONSHIP`
- `DENY_INSUFFICIENT_PRIVILEGE`

**Rules**
- Must be explainable: “Allowed because Campaign Moderator”, etc.
- Keep role→permission mapping centralized and testable.

---

### Layer 5 — Default Deny
**Purpose**
- If no allow matched, deny.

**Reason codes**
- `DENY_DEFAULT`

---

## 6) Data Visibility for List/Search Endpoints (Critical)
Most SaaS leaks occur in list/search endpoints. Treat this as first-class.

**Two-step rule**
1) Authorize the action itself: `idea.list`
2) Apply a **visibility filter** so results include only resources the user can see.

**Implement**
- `VisibilityFilterBuilder` (or similar) that returns query predicates:
    - campaigns/community scopes visible to subject
    - exclude restricted/private scopes
    - incorporate “public read” rules

**Consistency requirement**
- `GET /ideas/{id}` must enforce the same visibility logic as `GET /ideas?…`.

---

## 7) Logging, Audit, and Tracing
Every decision must be observable.

**Implement**
- Log `Decision.toLogFields(subject, action, resource, context)` for every authorization decision.
- For privileged actions (role assignment, bans, exports, deletions), write audit events containing:
    - actorMemberId (impersonator)
    - memberId (effective)
    - action, resource, scope
    - decisionId + reason

---

## 8) Caching & Performance (Plan Now, Implement Later)
Prefer caching **inputs** to authorization, not final decisions:
- member status, subscription state
- campaign state
- role assignments / moderator assignments
- ownership/membership relationships

Start with request-local memoization. If adding distributed caches later, require:
- safe invalidation (events) or versioning keys
- short TTL for ALLOW-like caches

---

## 9) Recommended Module/Package Structure (Per Service)

Suggested folder structure to mirror the layered pipeline:

- `authz/`
    - `AuthorizerImpl`
    - `gates/` (GateService)
    - `resolver/` (ResourceResolver)
    - `eligibility/` (EligibilityService)
    - `state/` (StateService, StatePolicy)
    - `grants/` (GrantService)
    - `mapping/` (role/bundle mapping)
    - `visibility/` (list/search filtering)

This keeps each layer isolated and testable.

---

## 10) Implementation Deliverables (Developer Checklist)

### Deliverable 1 — Shared contract library
- Use `authz-core` types:
    - `Action`, `Subject`, `ResourceRef`, `AuthzContext`, `Decision`, `ReasonCode`, `Effect`, `Obligation`, `Authorizer`

### Deliverable 2 — Service enforcement pattern (PEP)
- One enforcement call near top of each service method.
- Ensure internal jobs and service-to-service calls also go through PEP.

### Deliverable 3 — PDP pipeline implementation
Implement these interfaces (per service or shared decision service later):
- `GateService`
- `ResourceResolver`
- `EligibilityService`
- `StateService` + `StatePolicy`
- `GrantService` + `PermissionMapping`
- `Authorizer` implementation that runs the layers in order

### Deliverable 4 — Policy matrix for top actions
Start with 10–20 critical actions:
- `member.ban`, `member.unban`
- `campaign.launch`, `campaign.update_settings`
- `idea.edit`, `idea.delete`
- `idea.moderate.hide`
- `role.assign` / `permission.manage`

### Deliverable 5 — Test suite
For each critical action:
- allow cases (correct role/relationship)
- deny cases (banned, readonly, expired, wrong scope, missing membership)

---

## 11) Pitfalls to Avoid
- Authorization only in controllers (bypass via internal calls/jobs)
- Per-item auth checks in list endpoints (slow/inconsistent)
- Undefined precedence (owner vs readonly vs admin override)
- Role checks scattered across codebase (no single source of truth)
- Missing reason codes (support cannot debug)

---

## 12) Next Steps
1) Build an Action Catalog and select top 12 critical actions.
2) For each critical action, write:
    - required scope
    - hard denies
    - state constraints
    - allow roles
    - allow relationships (owner/moderator)
    - audit reason codes
3) Implement layers 1–4 for those actions first and add tests.
4) Expand coverage module-by-module.
