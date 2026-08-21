#!/usr/bin/env python3
"""Standalone entrypoint for the Guardian Audit Collector.
## Input file

**Raw Kubernetes audit log** — one JSON object per line, written by `kube-apiserver` itself (not something you create). Example line:

```json
{"stage":"ResponseComplete","verb":"get","objectRef":{"resource":"secrets","namespace":"prod"},"user":{"username":"system:serviceaccount:prod:backup-sa"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-07-29T10:14:02Z"}
```

Its location is whatever `AUDIT_LOG_PATH` points to (or wherever `discover.py` auto-finds it). This file grows continuously as the cluster runs — the collector never modifies it, only reads it.

## Output files

Three files get written, all under whatever directory you configure (default `/data/`):

| File | What it is |
|---|---|
| `guardian_audit.json` (`OUTPUT_PATH`) | **The real deliverable** — aggregated per-ServiceAccount permission usage. This is what the next Guardian stage (Permission Analyzer) will consume. |
| `.audit_scan_state.json` (`STATE_PATH`) | Internal bookkeeping — just `{"offset": ..., "inode": ...}`. You never read this yourself. |
| `guardian_collector_errors.log` (`ERROR_LOG_PATH`) | Debug log of malformed lines only. Empty in normal operation. |

## What you need to do to actually run it

**1. Python environment**
```bash
cd guardian-collector
pip install -r requirements.txt   # nothing required; PyYAML optional
```

**2. Point it at a real audit log.** This is the one thing that genuinely needs your input — the collector can't invent this. Depends on where you're running it:

- **If you're on the kube-apiserver host/control-plane node directly** → don't set `AUDIT_LOG_PATH` at all, discovery will find it automatically via `/proc/<pid>/cmdline` or the static manifest.
- **If you're running this in a separate container** (e.g. eventually alongside the rest of Guardian) → you must bind-mount the audit-log directory in, and set:
  ```
  AUDIT_LOG_PATH=/path/inside/container/audit.log
  ```
- **If you're testing locally with `kind`** → your cluster almost certainly isn't emitting an audit log at all yet by default. You need to:
  1. Write an actual `audit-policy.yaml` (the collector doesn't ship one — this is a real decision you have to make, e.g. `Metadata` level for `secrets`/`configmaps`).
  2. Add the `kind-config.yaml` snippet from the README (`extraMounts` + `kubeadmConfigPatches` with `--audit-log-path` and `--audit-policy-file`) and recreate the cluster with it.
  3. Set `AUDIT_LOG_PATH` to wherever that mount lands.

**3. Set the rest of your config** (optional — all have defaults) via `.env` or exported env vars — copy `.env.example` and adjust `TARGET_NAMESPACE`, `SCAN_INTERVAL_SECONDS`, etc. if the defaults don't fit.

**4. Make sure the output directory is writable**, e.g. `mkdir -p /data` (or point `OUTPUT_PATH`/`STATE_PATH`/`ERROR_LOG_PATH` somewhere you can write to, like a local folder while testing).

**5. Run it:**
```bash
python run.py --once     # one scan, good for first-time testing
python run.py             # continuous loop, for real use
```

If you don't have a live cluster handy yet, you can sanity-check the whole pipeline right now with a fake log file — just point `AUDIT_LOG_PATH` at any file containing lines like the example above, the way I did in the smoke test earlier. That's the fastest way to confirm your config is wired correctly before touching real cluster infrastructure.

"""

import sys

from collector.audit_collector import run_forever, run_once

if __name__ == "__main__":
    if "--once" in sys.argv:
        run_once()
    else:
        run_forever()
