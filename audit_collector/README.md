# Guardian — Node : Audit & Data Collector


```text
Kubernetes Audit Logs
        ↓
Audit Collector   <-- this component
        ↓
Normalized/Aggregated JSON
        ↓
Permission Analyzer
        ↓
Risk Scorer
        ↓
Policy Generator
```

## What this component does — and does not do

It collects, parses, filters, normalizes, and aggregates Kubernetes audit
events into a compact JSON file describing **what permissions each
ServiceAccount actually used**, how often, and when each was last
observed.

It **never**:
- decides that a permission is excessive or should be revoked,
- modifies RBAC,
- generates RBAC YAML,
- calls an LLM, or
- consumes raw audit logs downstream — the whole point of this component
  is to shrink potentially gigabytes of raw audit log into a small,
  structured JSON file *before* anything resembling an LLM sees it.

Those decisions belong to the downstream Permission Analyzer and Risk
Scorer.

---

## 1. How Kubernetes audit logs work (background)

The kube-apiserver can be configured to write one JSON object per line
for every API request it handles, controlled by:

- `--audit-log-path=<file>` — where to write (or `-` for stdout)
- `--audit-policy-file=<file>` — an `AuditPolicy` resource that decides,
  per rule, what audit **level** to record: `None`, `Metadata`,
  `Request`, or `RequestResponse`. Guardian's architecture calls for
  **`Metadata`-level** logging on sensitive resources like `secrets` —
  i.e. record *that* a ServiceAccount read a secret and when, never the
  secret's contents. This collector never records `requestObject` /
  `responseObject` bodies regardless of what level produced the event,
  as a second line of defense.
- `--audit-log-maxsize`, `--audit-log-maxbackup`, `--audit-log-maxage` —
  standard log-rotation knobs. Rotation typically produces a *new* file
  (new inode); some rotation strategies (`copytruncate`-style) instead
  truncate the existing file in place. This collector detects both (see
  §4).

Each event carries (among other fields) `stage` (request lifecycle
phase), `verb`, `objectRef` (what was acted on), `user` (who acted),
`responseStatus`, and a timestamp. Not every field is present on every
event — see §3.

This collector does **not** modify the cluster's audit policy. If your
policy doesn't emit `Metadata`-level (or richer) events for the
resources you care about, no ServiceAccount usage will be visible for
them; that's a cluster-configuration decision outside this component's
scope (spec Q8).

---

## 2. Architecture / module layout

```text
collector/
├── audit_collector.py   # orchestration: run_once() / run_forever()
├── parser.py             # raw JSON line -> AuditEvent, all filtering
├── aggregator.py          # AuditEvent list -> aggregate dict (in-memory)
├── state.py               # scanner offset persistence + rotation detection
├── models.py               # PermissionKey, AuditEvent, ScanStats dataclasses
├── config.py                # env-var configuration
├── discover.py               # audit-log path auto-discovery
└── output.py                   # atomic JSON read/write, schema conversion
tests/
├── test_parser.py        # event parsing/filtering, all required cases
├── test_filtering.py      # namespace scoping, special-verb handling
├── test_aggregation.py     # permission identity, quarterly buckets
└── test_state.py            # offset persistence, rotation, no double-count
```

Each module is independently importable/testable. Another Guardian
component can call:

```python
from collector.audit_collector import run_once
stats = run_once()  # one scan cycle; writes/updates OUTPUT_PATH
```

---

## 3. Event handling details

- **Stage filter**: only `stage == "ResponseComplete"` events are
  considered (a completed request).
- **Success filter**: `200 <= responseStatus.code < 300` — never a bare
  `== 200` check, since `create` commonly returns `201` and `delete`
  commonly returns `204`.
- **ServiceAccount identification**: `user.username` must match
  `system:serviceaccount:<namespace>:<name>`. Everything else
  (`system:apiserver`, `system:node:*`, human/admin users, ...) is
  ignored for the workload-usage dataset.
- **Permission identity** is the triple `(apiGroup, resource, verb)` —
  never verb alone. `get pods`, `get secrets`, and `list pods` are three
  distinct permissions.
- **apiGroup**: missing/absent `objectRef.apiGroup` normalizes to `""`
  (the core/legacy API group). Never invented otherwise.
- **Namespace**: `objectRef.namespace` is preserved when present; when
  absent (cluster-scoped resources: `nodes`, `clusterroles`, ...) the
  resource's namespace is recorded as `null` — **never** defaulted to
  `"default"`.
- **`TARGET_NAMESPACE`** filters by the **ServiceAccount's own**
  namespace (from its username), not the object's namespace, since a
  ServiceAccount belongs to exactly one namespace but may act on
  cluster-scoped or cross-namespace objects.
- **`watch` / `proxy` / `connect`**: recorded under a separate
  `special_operations` section per ServiceAccount (keyed by verb, same
  count/last_seen shape as `permissions_used`) rather than folded into
  `permissions_used` or silently relabeled — these don't map cleanly
  onto a single normal RBAC verb check the way `get`/`list`/`create`/
  `delete` do.
- **Malformed lines**: caught, logged to `ERROR_LOG_PATH` with enough
  context to debug (never raw sensitive content), and skipped — a single
  bad line never crashes the collector.

---

## 4. Incremental reading & rotation

The collector never rereads the whole log. It persists
`{"offset": <bytes>, "inode": <inode>}` to `STATE_PATH` after each scan
and seeks there next time. On each scan it reconciles the stored state
against the live file:

- if `offset > current file size` → log was rotated/truncated → reset to 0
- if the file's inode changed → log was rotated (new file) → reset to 0
- otherwise → resume from `offset`

This is independent from — and never conflated with — the aggregated
ServiceAccount statistics in `OUTPUT_PATH`, which persist across restarts
and rotations so history is never lost (spec §17–18).

---

## 5. Output schema

`OUTPUT_PATH` (default `/data/guardian_audit.json`) is written atomically
(temp file → fsync → `os.replace`) so downstream consumers never see a
partial write:

```json
{
  "generated_at": "2026-08-20T09:40:00Z",
  "time_window": { "start": "2026-07-01T10:00:00Z", "end": "2026-08-20T09:40:00Z" },
  "service_accounts": [
    {
      "service_account": "backup-sa",
      "namespace": "prod",
      "permissions_used": [
        {
          "api_group": "",
          "resource": "secrets",
          "verb": "get",
          "count": 45231,
          "first_seen": "2026-07-01T10:00:00Z",
          "last_seen": "2026-07-29T10:14:02Z"
        }
      ],
      "lifetime_stats": {
        "get": { "count": 45231, "last_seen": "2026-07-29T10:14:02Z" }
      },
      "quarterly_usage": {
        "2026-Q3": {
          "start_date": "2026-07-01",
          "end_date": "2026-09-30",
          "verb_counts": { "get": 12560, "list": 3210 },
          "resources_touched": { "secrets": 2710, "pods": 1765 }
        }
      },
      "special_operations": [
        { "api_group": "", "resource": "pods", "verb": "watch", "count": 88, "first_seen": "...", "last_seen": "..." }
      ]
    }
  ]
}
```

`lifetime_stats` (verb-only) is kept **in addition to** — never instead
of — `permissions_used` (which carries the resource dimension), since
collapsing to verb-only loses exactly the information the Permission
Analyzer needs (`get pods` vs `get secrets`).

---

## 6. Configuration

See `.env.example`. Key variables:

| Variable | Default | Purpose |
|---|---|---|
| `AUDIT_LOG_PATH` | auto-discovered | raw audit log location |
| `OUTPUT_PATH` | `/data/guardian_audit.json` | aggregated Guardian output |
| `STATE_PATH` | `/data/.audit_scan_state.json` | scanner offset |
| `ERROR_LOG_PATH` | `/data/guardian_collector_errors.log` | malformed-event debug log |
| `TARGET_NAMESPACE` | `*` (all) | restrict collection to one namespace |
| `SCAN_INTERVAL_SECONDS` | `30` | polling interval for continuous mode |

## 7. Running it

```bash
pip install -r requirements.txt   # no required deps; PyYAML optional
python run.py --once              # single scan, then exit
python run.py                     # continuous polling loop (default)
```

Or import and call directly from another Guardian component:

```python
from collector.audit_collector import run_once
run_once()
```

### Running the tests

```bash
python -m unittest discover -s tests -v
```

---

## 8. Audit-log discovery

Resolution order (never falls back to a hardcoded guess like
`/var/log/audit.log`):

1. `AUDIT_LOG_PATH` env var, if set.
2. Scan `/proc/<pid>/cmdline` for a running `kube-apiserver` process and
   extract its `--audit-log-path=` argument.
3. Parse `/etc/kubernetes/manifests/kube-apiserver.yaml` for the same
   flag (PyYAML if available, dependency-free regex scan otherwise).
4. If all of the above fail, the collector raises a clear error naming
   what it checked and suggesting:
   ```bash
   kubectl -n kube-system get pod -l component=kube-apiserver -o yaml | grep audit-log-path
   ```
   and setting `AUDIT_LOG_PATH` explicitly. It does **not** shell out to
   `kubectl` automatically — the collector may not have a kubeconfig or
   RBAC access from inside the Guardian container, and guessing
   credentials/paths is exactly the kind of fabrication to avoid.

---

## 9. Exposing the audit log in a Kind cluster (PoC)

`kind` runs the control plane inside a Docker container, so the audit
log does **not** exist on your Mac/Linux host filesystem by default —
only inside that container. Two supported approaches:

**Option A — run the collector on the kind control-plane node itself**
(simplest for a PoC): `docker exec` into the control-plane container (or
run the collector as a static pod / DaemonSet scheduled there) — `Method
1` (proc/cmdline) discovery then works unmodified.

**Option B — mount a host path into the kind node, and bind-mount that
into the Guardian container.** In your `kind` cluster config, add an
`extraMounts` entry on the control-plane node so the audit log directory
is visible on the Docker host, then mount that host path into the
Guardian container:

```yaml
# kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: /tmp/kind-audit-logs
        containerPath: /var/log/kubernetes/audit
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            audit-log-path: /var/log/kubernetes/audit/audit.log
            audit-policy-file: /etc/kubernetes/policies/audit-policy.yaml
          extraVolumes:
            - name: audit-log
              hostPath: /var/log/kubernetes/audit
              mountPath: /var/log/kubernetes/audit
              pathType: DirectoryOrCreate
            - name: audit-policy
              hostPath: /etc/kubernetes/policies
              mountPath: /etc/kubernetes/policies
              readOnly: true
              pathType: DirectoryOrCreate
```

With that in place, `/tmp/kind-audit-logs` on your Docker host contains
the live audit log, and you bind-mount it into the Guardian container
(e.g. `-v /tmp/kind-audit-logs:/data/audit:ro`) and set
`AUDIT_LOG_PATH=/data/audit/audit.log`.

You'll also need an actual `audit-policy.yaml` (not provided here — this
repository doesn't assume one exists; author it per your Guardian
security requirements, e.g. `Metadata` level for `secrets`/`configmaps`,
`RequestResponse` or `None` elsewhere as appropriate) at the host path
referenced above.

---

## 10. Example input → output

Input (two raw audit-log lines):

```json
{"apiVersion":"audit.k8s.io/v1","stage":"ResponseComplete","verb":"get","objectRef":{"resource":"secrets","namespace":"prod"},"user":{"username":"system:serviceaccount:prod:backup-sa"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-07-29T10:14:02Z"}
{"apiVersion":"audit.k8s.io/v1","stage":"ResponseComplete","verb":"create","objectRef":{"resource":"pods","namespace":"prod","apiGroup":""},"user":{"username":"system:serviceaccount:prod:backup-sa"},"responseStatus":{"code":201},"requestReceivedTimestamp":"2026-07-29T10:15:00Z"}
```

Output (`guardian_audit.json`, abbreviated):

```json
{
  "generated_at": "2026-08-20T09:40:00Z",
  "time_window": { "start": "2026-07-29T10:14:02Z", "end": "2026-08-20T09:40:00Z" },
  "service_accounts": [
    {
      "service_account": "backup-sa",
      "namespace": "prod",
      "permissions_used": [
        { "api_group": "", "resource": "pods", "verb": "create", "count": 1, "first_seen": "2026-07-29T10:15:00Z", "last_seen": "2026-07-29T10:15:00Z" },
        { "api_group": "", "resource": "secrets", "verb": "get", "count": 1, "first_seen": "2026-07-29T10:14:02Z", "last_seen": "2026-07-29T10:14:02Z" }
      ],
      "lifetime_stats": {
        "get": { "count": 1, "last_seen": "2026-07-29T10:14:02Z" },
        "create": { "count": 1, "last_seen": "2026-07-29T10:15:00Z" }
      },
      "quarterly_usage": {
        "2026-Q3": {
          "start_date": "2026-07-01", "end_date": "2026-09-30",
          "verb_counts": { "get": 1, "create": 1 },
          "resources_touched": { "secrets": 1, "pods": 1 }
        }
      },
      "special_operations": []
    }
  ]
}
```

## 11. How downstream Guardian components use this

The Permission Analyzer reads `OUTPUT_PATH`, fetches (or is given) each
ServiceAccount's actual RBAC `Role`/`ClusterRole` bindings, and compares
the two: any RBAC rule with **no corresponding entry** in
`permissions_used` (accounting for `special_operations` separately) is a
candidate for the Risk Scorer to evaluate. This collector produces only
the "actually used" side of that comparison — it does not fetch RBAC and
does not perform the comparison itself.
