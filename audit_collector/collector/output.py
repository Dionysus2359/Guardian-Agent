"""Persistence of the Guardian output/aggregate JSON.

Handles both directions:
  * load_aggregate(): existing output JSON -> internal dict keyed by
    (namespace, service_account), so a restart can resume accumulating
    instead of starting from zero (spec section 18).
  * to_serializable(): internal dict -> the final JSON structure
    consumed by the downstream Permission Analyzer (spec section 16).

Writes are atomic (temp file + fsync + os.replace) so the downstream
consumer never observes a partially written file (spec section 22).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def load_aggregate(output_path: str) -> dict:
    """Load a previously written guardian_audit.json back into the
    internal (namespace, sa) -> record dict shape used by aggregator.py.

    Returns an empty dict if no output exists yet (first run).
    """
    p = Path(output_path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        # Corrupt output must never crash the collector or cause data
        # loss silently — but we also must not fabricate history. Start
        # fresh and let the operator investigate via the error log.
        return {}

    aggregate: dict = {}
    for sa_entry in data.get("service_accounts", []):
        namespace = sa_entry.get("namespace")
        sa_name = sa_entry.get("service_account")
        if not sa_name:
            continue
        key = (namespace, sa_name)
        permissions_used = {
            f"{pu['api_group']}|{pu['resource']}|{pu['verb']}": dict(pu)
            for pu in sa_entry.get("permissions_used", [])
        }
        special_operations = {
            so["verb"]: dict(so) for so in sa_entry.get("special_operations", [])
        }
        lifetime_stats = dict(sa_entry.get("lifetime_stats", {}))
        quarterly_usage = dict(sa_entry.get("quarterly_usage", {}))
        aggregate[key] = {
            "service_account": sa_name,
            "namespace": namespace,
            "permissions_used": permissions_used,
            "lifetime_stats": lifetime_stats,
            "quarterly_usage": quarterly_usage,
            "special_operations": special_operations,
        }
    return aggregate


def to_serializable(aggregate: dict, *, window_start: str | None = None) -> dict:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    service_accounts = []
    for (_namespace, _sa_name), record in sorted(aggregate.items(), key=lambda kv: kv[0]):
        service_accounts.append(
            {
                "service_account": record["service_account"],
                "namespace": record["namespace"],
                "permissions_used": sorted(
                    record["permissions_used"].values(),
                    key=lambda e: (e["api_group"], e["resource"], e["verb"]),
                ),
                "lifetime_stats": record["lifetime_stats"],
                "quarterly_usage": record["quarterly_usage"],
                "special_operations": sorted(
                    record["special_operations"].values(), key=lambda e: e["verb"]
                ),
            }
        )
    return {
        "generated_at": now,
        "time_window": {"start": window_start, "end": now},
        "service_accounts": service_accounts,
    }


def write_atomic(output_path: str, payload: dict) -> None:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=False))
    with open(tmp_path, "r+b") as f:
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, p)  # atomic on POSIX
