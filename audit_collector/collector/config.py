"""Configuration for the Guardian Audit Collector.

Every path and tunable is configurable via environment variables so the
collector can run unmodified on a control-plane host or inside the
Guardian container with the audit-log directory bind-mounted in.

Nothing here is project-specific/hardcoded (see spec section 24).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"Environment variable {name}={raw!r} is not a valid integer")


@dataclass(frozen=True)
class Config:
    # Where the raw Kubernetes audit log lives. If unset, discover.py will
    # attempt auto-discovery (proc/cmdline, static manifest, kubectl hint).
    audit_log_path: str | None = field(
        default_factory=lambda: os.environ.get("AUDIT_LOG_PATH") or None
    )

    # Final machine-readable Guardian output AND the persisted aggregate
    # (spec section 16/17 — the output file doubles as the durable
    # aggregate store for this JSON-based PoC; see aggregator.py).
    output_path: str = field(
        default_factory=lambda: os.environ.get(
            "OUTPUT_PATH", "/data/guardian_audit.json"
        )
    )

    # Scanner offset/state file (spec section 5) — NOT the same as the
    # aggregated statistics. Tracks only "how far into the raw log have
    # we read".
    state_path: str = field(
        default_factory=lambda: os.environ.get(
            "STATE_PATH", "/data/.audit_scan_state.json"
        )
    )

    # "*" (default) analyzes every namespace. A concrete namespace value
    # restricts collection to that namespace only. Explicitly configurable
    # per spec section 12 — must never silently default to "default".
    target_namespace: str = field(
        default_factory=lambda: os.environ.get("TARGET_NAMESPACE", "*")
    )

    # How often (seconds) the continuous polling loop rescans the log.
    scan_interval_seconds: int = field(
        default_factory=lambda: _env_int("SCAN_INTERVAL_SECONDS", 30)
    )

    # Directory for the malformed/error debug log (spec section 19/23).
    error_log_path: str = field(
        default_factory=lambda: os.environ.get(
            "ERROR_LOG_PATH", "/data/guardian_collector_errors.log"
        )
    )

    def matches_namespace(self, namespace: str | None) -> bool:
        """Whether an event's namespace passes the configured filter."""
        if self.target_namespace == "*":
            return True
        return namespace == self.target_namespace

    def ensure_parent_dirs(self) -> None:
        for p in (self.output_path, self.state_path, self.error_log_path):
            Path(p).parent.mkdir(parents=True, exist_ok=True)


def load_config() -> Config:
    return Config()
