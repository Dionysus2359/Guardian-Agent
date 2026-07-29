# Project Guardian — Design Document
### Agentic AI for Autonomous RBAC Hardening and Least Privilege Governance in Kubernetes
HPE Career Preview Program (CPP2), FY2026 — B.Tech Internship Project

*Status: Draft v0.2 — first full version. Living document; to be refined as each component owner locks in implementation details.*

---

## 1. Problem Statement

Manual Kubernetes RBAC auditing is slow, error-prone, and does not scale with cluster size or team velocity. In practice:

- **60%** of clusters contain ServiceAccounts with admin-level rights they do not need.
- **90%** of granted permissions are never actually exercised.
- The average breach cost tied to privilege escalation is estimated at **$4.5M** (IBM, 2025).

No one revokes unused permissions because administrators fear breaking production workloads — the cost of being wrong (an outage) feels higher than the cost of doing nothing (a latent, usually-invisible risk). This asymmetry is what causes permission sprawl to accumulate unchecked.

## 2. Motivation

Project Guardian shifts RBAC hygiene from a manual, fear-driven, point-in-time audit into an **autonomous, continuous, least-privilege governance loop**. Instead of a human periodically (or never) reviewing permissions, an AI agent:

1. Continuously observes what permissions exist vs. what is actually used.
2. Reasons about whether the gap is genuinely excessive or a legitimate edge case (e.g., a disaster-recovery controller that is dormant 350 days a year).
3. Acts by generating and applying a tightened, least-privilege policy.
4. Governs by verifying the change didn't break anything, and continuing to watch for the permission drifting back open.

The differentiator over a simple "delete anything unused" script is the reasoning step — Guardian should behave like a careful security engineer, not a blunt linter.

## 3. Requirements

### Functional
- FR1: Ingest RBAC/permission context from at least: live K8s API state, static manifests, and SubjectAccessReviews. (Historical audit logs are a fourth pillar — see §8 and §13 for phasing.)
- FR2: Reason over a ServiceAccount's granted-vs-used permissions using an LLM and produce a structured, machine-parseable verdict (not free text).
- FR3: Generate valid, minimal Role/RoleBinding YAML reflecting only the necessary permissions.
- FR4: Validate generated YAML against a strict safety policy (no wildcards, no unintended cluster-admin escalation) before it is ever applied.
- FR5: Apply the generated policy to a live cluster and verify post-apply health via SAR checks.
- FR6: Detect configuration drift against a previously approved baseline. Auto-revert only low-risk drift; route any drift touching a dangerous verb, high-value resource, wildcard, or critical namespace to human adjudication rather than assuming intent either way.
- FR7: Route high-risk or low-confidence verdicts to a human approval queue instead of auto-applying.
- FR8: Log every action Guardian itself takes (a self-audit trail), independent of the K8s audit log.

### Non-functional
- NFR1: The orchestration layer must be resilient to LLM hallucination — no unvalidated model output ever reaches the cluster.
- NFR2: Must run entirely on local hardware (4-bit quantized ~8B model, e.g. `qwen3:8b` via Ollama, within a 6GB VRAM budget) — no cluster data leaves the machine.
- NFR3: The recursion/retry depth of any agent loop must be bounded (hard cap) to prevent runaway execution.
- NFR4: Guardian's own operating ServiceAccount must itself follow least privilege — it should not require cluster-admin to function.
- NFR5: Every state-changing action must be reversible (a backup of the prior config must exist before any apply).

## 4. High-Level Design

Four layers, matching the architecture from kickoff (see accompanying `project_guardian_architecture_flow.mermaid`):

| Layer | Responsibility | Owner |
|---|---|---|
| **Data Layer** | Ingests the 4 pillars of context: historical audit logs, static manifests, live RBAC API state, SubjectAccessReviews | Data Ingestion |
| **Agent Layer** | Log Collector → Permission Analyzer → Risk Scorer → Policy Generator, as sequential LangGraph nodes | Om (Orchestrator) |
| **AI Engine** | Local Ollama model (qwen3:8b, 4-bit quantized) invoked by the agent nodes, with chain-of-thought reasoning captured in state | Om (Orchestrator) |
| **Execution & Governance Layer** | Validates, applies, health-checks, backs up, and continuously drift-checks policies against the `kind` cluster | Execution/Rollback team |
| **Simulation Layer** | Scripted privilege-escalation attempts used both as a demo and as a regression test suite | Attack Simulation team |
| **Presentation Layer** | Streamlit dashboard reading blast-radius before/after metrics via a small FastAPI wrapper | Dashboard team |

The system operates as a loop: **Observe → Reason → Act → Govern**, not a one-shot pipeline. Govern feeds back into Observe (drift detection re-triggers analysis).

## 5. Component Design

**Log Collector Node** — pure Python, no LLM call. Normalizes the four ingestion pillars into one internal shape per ServiceAccount: `{granted_permissions, used_permissions, source_confidence}`.

**Permission Analyzer Node** — first LLM call. Given the normalized shape, classifies each granted-but-unused permission as `likely-safe-to-revoke`, `needs-context` (e.g., disaster-recovery pattern), or `dangerous-verb-present` (bind/impersonate/escalate, wildcard, cluster-admin).

**Risk Scorer Node** — combines the Analyzer's classification with a deterministic rule layer that overrides the LLM's own confidence whenever the change touches any of the following. This rule is intentionally hard-coded, not model-judged — don't trust the LLM alone on the highest-stakes calls:

- **Dangerous verbs:** `bind`, `impersonate`, `escalate`, `approve`
- **High-value resources:** `secrets`, `rolebindings`, `clusterroles`, `certificatesigningrequests`
- **Wildcards:** any `*` in `verbs`, `resources`, or `apiGroups`
- **Critical namespaces:** any change targeting `kube-system` or `kube-public`

If any of these are touched, the risk score automatically maxes out and the change is forced into the Human Approval Queue — regardless of the LLM's stated confidence. This same rule set is reused verbatim by the Drift Detector (below), not just at initial policy generation time.

**Policy Generator Node** — second LLM call, constrained to emit only the structured JSON contract in §6, which a deterministic Python template then converts into actual Role/RoleBinding YAML. The LLM never writes YAML directly — it only picks *which permissions to keep*; a template generates the syntax. This removes an entire class of hallucination risk (malformed YAML, invented API groups).

**YAML Validator** (Execution layer, but tightly coupled to the Agent output) — a non-negotiable Python check: rejects wildcards (`*`), rejects any change that grants `cluster-admin` or dangerous verbs the original didn't already have, rejects malformed API groups against a known-good list. Failing validation routes to the human queue, never silently drops the change.

**Execution Controller** — applies validated YAML via the K8s Python client, immediately backs up the prior config, then runs the health check.

**Drift Detector** — a scheduled (or manually triggered, for the PoC) re-scan comparing live RBAC state per SA against its last *approved* baseline in the Baseline Store. A mismatch means a permission Guardian previously revoked has reappeared, through some channel Guardian didn't perform itself. Guardian does **not** try to guess whether that was an attack, an admin mistake, or a legitimate emergency override — that's undecidable from cluster state alone. Instead it reuses the exact same high-risk rule set from the Risk Scorer above:

- Drift touching a **low-risk** permission → auto-revert immediately (impact of being wrong either way is small).
- Drift touching a **high-risk** permission (dangerous verb, high-value resource, wildcard, or critical namespace) → **never** auto-revert *and* never silently accept it either. It's frozen and sent to the Human Approval Queue with two explicit options: confirm ("this was intentional, promote it to the new approved baseline") or reject ("revert to the prior baseline"). Auto-reverting instantly here is just as risky as auto-accepting — it could undo something an on-call engineer just added on purpose during an active incident.

## 6. APIs / Internal Contracts

Since every layer is owned by a different person, these contracts are the actual interface — treat them as fixed once agreed, version them if they need to change.

**Ingestion → Orchestrator**
```json
{
  "service_account": "backup-controller-sa",
  "namespace": "ops",
  "cluster_role": false,
  "granted_permissions": [
    {"resource": "secrets", "verb": "list", "api_group": ""},
    {"resource": "rolebindings", "verb": "create", "api_group": "rbac.authorization.k8s.io"}
  ],
  "used_permissions": [
    {"resource": "secrets", "verb": "list", "last_used": "2026-06-01"}
  ],
  "source": "live_api"
}
```

**Orchestrator internal — LLM forced-output contract**
```json
{
  "verdict": "revoke | keep | keep_with_alert | escalate_to_human",
  "risky_permissions": [
    {"resource": "rolebindings", "verb": "create", "reason": "unused 90 days, escalation-capable verb"}
  ],
  "reasoning": "short natural-language justification",
  "confidence": 0.0
}
```

**Orchestrator → Execution Controller**
```json
{
  "action": "apply | dry_run",
  "service_account": "backup-controller-sa",
  "namespace": "ops",
  "new_role_yaml": "<generated YAML string>",
  "baseline_id": "uuid-of-backup-to-restore-if-this-fails",
  "run_id": "<LangGraph thread_id for this reasoning run>"
}
```
`run_id` is the LangGraph `thread_id` that produced this decision. The Execution layer logs it alongside every apply/backup/health-check it performs, so a failed or disputed deployment can be traced straight back to the exact reasoning trace that generated it — no guessing which run caused which outcome.

**Execution / Baseline Store → Dashboard**
`GET /get-blast-radius?service_account=backup-controller-sa` →
```json
{
  "before": {"permission_count": 14, "risk_score": 78},
  "after": {"permission_count": 3, "risk_score": 12},
  "status": "applied | pending_approval | reverted"
}
```

## 7. State Management ("Database Schema")

Guardian is stateful across three distinct concerns — don't conflate them into one table:

- **LangGraph run state** — checkpointed via LangGraph's built-in SQLite checkpointer, keyed by a `thread_id` (recommend `<namespace>/<service_account>/<run_timestamp>`). Lets you resume or inspect intermediate reasoning steps per run, which is also good demo material ("here's the model's actual reasoning trace").
- **Baseline Store** — a small SQLite table, `policy_baselines(id, service_account, namespace, approved_yaml, applied_at, status, last_modified_via)`, holding the *currently approved* least-privilege config per SA. `last_modified_via` is one of `guardian_auto | human_approved | unknown_drift` — this is what lets the Drift Detector tell "Guardian did this" apart from "something changed this out-of-band," which is the whole basis for the drift-adjudication logic in §5.
- **Backup files** — the literal prior YAML, written to disk before every apply: `./guardian_backups/<namespace>/<service_account>/<timestamp>.yaml`. Cheap, human-inspectable, and doesn't depend on SQLite being healthy to recover from.
- **Guardian's self-audit log** — `guardian_actions(id, run_id, timestamp, service_account, action_type, verdict, yaml_diff, approved_by)`. `run_id` links each logged action back to the exact LangGraph checkpoint (thread) that produced it, so a disputed or failed deployment can be traced straight to its reasoning trace. This table is Guardian's own accountability trail, independent of the K8s audit log, and directly answers "who audits the auditor."

If continuous polling is added later (post-PoC), incoming audit events get buffered in an append-only table or JSONL file before being batched to the LLM — don't call the model per single log line.

## 8. Data Flow

The full loop: **Observe → Reason → Act → Govern**, sourced from four ingestion pillars (this is the direct answer to "beyond audit logs"):

1. **Historical Audit Logs** — what was actually used, over time.
2. **Static Manifest Analysis** — what was *intended*, parsed from Git before deployment.
3. **Dynamic API Polling** — what currently exists, live, in the cluster.
4. **SubjectAccessReviews** — the definitive, engine-resolved ground truth for "can this identity actually do this."

These four are deliberately redundant with each other — that's the point. Audit logs alone miss permissions that are correct-but-rarely-triggered; manifests alone miss drift introduced after deployment; live API state alone doesn't tell you what's *used* vs. just *granted*; SAR alone doesn't explain *why* something is risky. Guardian's Log Collector node reconciles all four into one view before reasoning starts.

See `project_guardian_architecture_flow.mermaid` for the full diagram, including the three distinct feedback loops (deployment-safety rollback, RBAC's own real-time enforcement, and drift-detection self-healing) — these are easy to conflate and are kept explicitly separate in the diagram for that reason.

## 9. Edge Cases & Error Handling

| Scenario | Handling |
|---|---|
| LLM hallucinates a wildcard or non-existent API group | Deterministic YAML Validator rejects it before it ever reaches the cluster; routed to human queue, never silently dropped. |
| Agent gets stuck in a retry loop trying to "fix" a rejected policy | Hard recursion cap (e.g., 3 attempts), then auto-abort to human review. |
| Tightened policy breaks legitimate app functionality | Health check fails → revert to last-known-good baseline → flag for human review. Not a security failure — an expected safety-net path. |
| Rollback itself fails (e.g., API server unreachable mid-revert) | Do not fail silently. Mark the SA `NEEDS_MANUAL_INTERVENTION` and alert loudly — never assume success. |
| A human manually edits the RBAC object while Guardian is mid-run | Use `resourceVersion` optimistic-concurrency checks before applying; abort and re-observe if the object changed underneath you. |
| LLM verdict confidence is low | Route to human approval queue regardless of the verdict itself — low confidence is its own risk signal. |
| Guardian's own ServiceAccount is over-permissioned | Explicitly scope Guardian's own operating role to least privilege as part of setup — practice what it enforces. |
| A previously revoked permission reappears later (drift) — could be an attack, an admin mistake, or a deliberate emergency override | Guardian does not attempt to infer intent from cluster state alone — that's undecidable. It enforces a process boundary instead: only changes that flow through Guardian's own approval channel are trusted. Low-risk drift auto-reverts immediately; high-risk drift (per the §5 rule set) is frozen and always routed to a human to explicitly confirm-as-new-baseline or reject-and-revert. |

## 10. Trade-offs

- **Local LLM (qwen3:8b, 4-bit) vs. cloud API (e.g., OpenAI):** local sacrifices raw reasoning quality and speed for guaranteed data privacy — no cluster permission data or secrets metadata ever leaves the machine, which matters specifically because this is a security tool. Given the 6GB VRAM ceiling, this is also the only option that fits the hardware anyway.
- **LangGraph vs. CrewAI:** chose LangGraph for its low-level, cyclic state-machine model, giving strict deterministic control over the execution loop and straightforward human-in-the-loop interrupts. CrewAI's higher-level, delegation-style agent abstraction is a better fit for loosely-coupled creative tasks, not for a security-critical loop where every state transition needs to be inspectable and boundable. The four "agent roles" (Collector/Analyzer/Scorer/Generator) are implemented as LangGraph nodes sharing one state object, not as a second framework layered on top.
- **Direct `kubectl apply` vs. GitOps PR workflow:** direct apply is faster to build and sufficient for the PoC; a real production deployment should instead have Guardian open a pull request against the manifests repo for ArgoCD/Flux to sync, giving a human review gate and full version history for free. Documented here as the intended production path, not built in Phase 0.
- **Fully autonomous apply vs. risk-tiered human approval:** chose risk-tiered — auto-apply only for low-risk, non-escalation-capable changes; anything touching `bind`/`impersonate`/`escalate` or cluster-admin bindings requires human sign-off. Full autonomy is faster to demo but indefensible for a security tool; zero autonomy defeats the point of the project.
- **YAML analysis vs. SubjectAccessReviews:** static YAML shows configuration, not resolved behavior — RBAC rule composition (multiple roles, deny-by-default, aggregation) can make the effective permission different from what any single Role file suggests. SAR asks the K8s authorization engine directly, giving a definitive answer instead of an inferred one.

## 11. Alternatives Considered

- **Rule-based linter only (no LLM):** rejected as the primary mechanism — it would flag every unused permission identically, with no ability to distinguish "safe to revoke" from "dormant but legitimate" (e.g., disaster-recovery controllers). Kept as a deterministic *backstop* layer (the Risk Scorer's dangerous-verb rules), not the whole system.
- **Fully autonomous apply-everything agent:** rejected for the reasons in §10 — indefensible for a tool with write access to cluster security policy.
- **Cloud-hosted LLM:** rejected due to data-privacy requirements and hardware-cost constraints for a student project.
- **CrewAI as the orchestration framework:** rejected — see §10.

## 12. Testing Strategy

- **Unit tests:** YAML Validator (wildcard rejection, invalid API group rejection, cluster-admin escalation rejection); JSON contract schema validation between every layer boundary in §6.
- **Integration tests:** apply generated policy to a disposable namespace in `kind`; assert SAR results match expectations for both allowed and denied actions.
- **Adversarial / regression tests:** the Attack Simulation scripts double as a regression suite — after every Guardian run, replay known escalation patterns (`bind`, `impersonate`, `escalate` abuse) and assert they are denied post-tightening.
- **Failure-injection tests:** simulate a broken health check (assert deployment-safety rollback triggers), a failed rollback (assert loud alert + `NEEDS_MANUAL_INTERVENTION` state, not silent failure), and a low-confidence LLM verdict (assert it routes to human queue, not auto-apply).

## 13. Rollout Plan

Project runway extends through November, so Phases 1–3 below are genuine planned milestones for the internship, not just aspirational future-work filler — each is worth a rough time budget in the actual project plan, not only in this document.

- **Phase 0 — PoC (immediate, this week):** single ServiceAccount, single namespace, manual trigger, local `kind` cluster. Full Observe→Reason→Act→Govern loop for one golden-path scenario. Attack-simulation demo only if time permits after the core loop is solid.
- **Phase 1:** multiple ServiceAccounts across one namespace, scheduled (not manual) runs, live dashboard, drift detection running continuously rather than on-demand.
- **Phase 2:** multi-namespace coverage, GitOps PR-based apply instead of direct patch, human-approval queue wired to a real notification channel (e.g., Slack/email), full attack-catalog regression suite.
- **Phase 3 (stretch, if time remains before November):** multi-cluster support, continuous drift-detection daemon running as a proper controller/operator, admission-webhook integration for proactive (not just after-the-fact) blocking.

## 14. Future Improvements

- ValidatingAdmissionWebhook integration — block risky pod/policy creation proactively instead of only remediating after the fact.
- GitOps-native apply path (PR-based, ArgoCD/Flux-synced).
- Cross-referencing cloud IAM for workload-identity-federated ServiceAccounts.
- Distilling a smaller fine-tuned model from Guardian's own reasoning traces for faster, cheaper inference than the general-purpose 8B model.
- Multi-cluster, fleet-wide governance dashboard.

---
*Accompanying diagram: `project_guardian_architecture_flow.mermaid`*
