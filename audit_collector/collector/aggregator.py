"""Aggregation of parsed AuditEvents into the Guardian output schema.

The in-memory/on-disk representation mirrors spec section 16's
recommended structure, extended with a `lifetime_stats` verb-level view
(spec section 14) alongside the richer (apiGroup, resource, verb)
`permissions_used` view (spec section 9) — the verb-only view is kept
ADDITIONALLY, never as a replacement, since it loses information.

This module has no knowledge of files; audit_collector.py owns I/O via
output.py. That keeps aggregation logic independently testable.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterable

from .models import AuditEvent, PermissionKey, ScanStats

logger = logging.getLogger("guardian.collector.aggregator")


def _parse_ts(ts: str) -> datetime:
    # Kubernetes timestamps are RFC3339 with a trailing "Z".
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _quarter_label(dt: datetime) -> str:
    q = (dt.month - 1) // 3 + 1
    return f"{dt.year}-Q{q}"


def _quarter_bounds(label: str) -> tuple[str, str]:
    from datetime import timedelta

    year_str, q_str = label.split("-Q")
    year = int(year_str)
    q = int(q_str)
    start_month = (q - 1) * 3 + 1
    start = datetime(year, start_month, 1, tzinfo=timezone.utc)
    if start_month + 3 > 12:
        next_q_start = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        next_q_start = datetime(year, start_month + 3, 1, tzinfo=timezone.utc)
    end = next_q_start - timedelta(days=1)  # last calendar day of the quarter
    return start.date().isoformat(), end.date().isoformat()


def _blank_sa_record(namespace: str, service_account: str) -> dict:
    return {
        "service_account": service_account,
        "namespace": namespace,
        "permissions_used": {},  # keyed internally by "api_group|resource|verb"
        "lifetime_stats": {},  # keyed internally by verb
        "quarterly_usage": {},  # keyed by "YYYY-Qn"
        "special_operations": {},  # keyed by verb -> {count, last_seen}; watch/proxy/connect
    }


def _perm_key_str(key: PermissionKey) -> str:
    return f"{key.api_group}|{key.resource}|{key.verb}"


def apply_events(
    aggregate: dict,
    events: Iterable[AuditEvent],
    stats: ScanStats | None = None,
) -> dict:
    """Merge `events` into `aggregate` (mutated in place, and returned).

    `aggregate` uses the internal (dict-keyed) representation produced by
    `_blank_sa_record` / `output.load_aggregate` — call
    `output.to_serializable` before writing JSON.
    """
    for event in events:
        sa_key = (event.namespace_identity, event.service_account)
        record = aggregate.setdefault(
            sa_key, _blank_sa_record(event.namespace_identity, event.service_account)
        )

        try:
            dt = _parse_ts(event.timestamp)
        except ValueError:
            logger.error("Unparseable timestamp %r for %s — skipping event", event.timestamp, sa_key)
            continue

        perm_key = event.permission_key
        pk_str = _perm_key_str(perm_key)

        # --- permissions_used: (apiGroup, resource, verb) dimension ---
        target_bucket = record["special_operations"] if perm_key.is_special else record["permissions_used"]
        bucket_key = perm_key.verb if perm_key.is_special else pk_str
        entry = target_bucket.setdefault(
            bucket_key,
            {
                "api_group": perm_key.api_group,
                "resource": perm_key.resource,
                "verb": perm_key.verb,
                "count": 0,
                "first_seen": event.timestamp,
                "last_seen": event.timestamp,
            },
        )
        entry["count"] += 1
        if event.timestamp > entry["last_seen"]:
            entry["last_seen"] = event.timestamp
        if event.timestamp < entry["first_seen"]:
            entry["first_seen"] = event.timestamp

        # --- lifetime_stats: verb-only dimension (kept ADDITIONALLY) ---
        verb_entry = record["lifetime_stats"].setdefault(
            perm_key.verb, {"count": 0, "last_seen": event.timestamp}
        )
        verb_entry["count"] += 1
        if event.timestamp > verb_entry["last_seen"]:
            verb_entry["last_seen"] = event.timestamp

        # --- quarterly_usage ---
        q_label = _quarter_label(dt)
        q_start, q_end = _quarter_bounds(q_label)
        q_record = record["quarterly_usage"].setdefault(
            q_label,
            {"start_date": q_start, "end_date": q_end, "verb_counts": {}, "resources_touched": {}},
        )
        q_record["verb_counts"][perm_key.verb] = q_record["verb_counts"].get(perm_key.verb, 0) + 1
        q_record["resources_touched"][perm_key.resource] = (
            q_record["resources_touched"].get(perm_key.resource, 0) + 1
        )

        if stats is not None:
            stats.new_events_processed += 1
            stats.service_accounts_touched.add(f"{event.namespace_identity}/{event.service_account}")

    return aggregate
