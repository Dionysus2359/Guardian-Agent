"""Kubernetes audit-log path discovery (spec section 3).

Never invents a path such as /var/log/audit.log. Discovery order:

  1. AUDIT_LOG_PATH env var (explicit config always wins — config.py)
  2. Running kube-apiserver process: /proc/<pid>/cmdline
  3. Static kube-apiserver manifest: /etc/kubernetes/manifests/kube-apiserver.yaml
  4. Give up and report clearly that discovery failed, with a kubectl
     hint the operator can run themselves (we do not shell out to
     kubectl automatically — the collector may not have a kubeconfig
     inside the Guardian container, and guessing credentials/paths is
     exactly the kind of fabrication the spec forbids).

This module intentionally has no PyYAML *requirement*: the manifest is
parsed with a small, dependency-free scan for the `--audit-log-path=`
argument line, since we only need one scalar value, not a full parse.
If PyYAML is available it is used for a more robust parse.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("guardian.collector.discover")

_ARG_RE = re.compile(r"--audit-log-path=([^\s\x00]+)")


class AuditLogNotFoundError(RuntimeError):
    """Raised when no audit log path could be discovered or configured."""


def _scan_proc_for_apiserver() -> str | None:
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        cmdline_path = entry / "cmdline"
        try:
            raw = cmdline_path.read_bytes()
        except (OSError, PermissionError):
            continue
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="ignore")
        if "kube-apiserver" not in cmdline:
            continue
        match = _ARG_RE.search(cmdline)
        if match:
            logger.info("Discovered audit-log-path via /proc/%s/cmdline", entry.name)
            return match.group(1)
    return None


def _scan_static_manifest(
    manifest_path: str = "/etc/kubernetes/manifests/kube-apiserver.yaml",
) -> str | None:
    p = Path(manifest_path)
    if not p.exists():
        return None
    try:
        text = p.read_text()
    except OSError:
        return None

    try:
        import yaml  # optional; only used if present

        doc = yaml.safe_load(text)
        containers = (doc or {}).get("spec", {}).get("containers", [])
        for c in containers:
            for arg in c.get("command", []) + c.get("args", []):
                m = _ARG_RE.search(arg)
                if m:
                    logger.info("Discovered audit-log-path via static manifest (YAML parse)")
                    return m.group(1)
    except Exception:  # pragma: no cover - PyYAML absent or unexpected shape
        pass

    # Dependency-free fallback: scan raw text for the flag.
    m = _ARG_RE.search(text)
    if m:
        logger.info("Discovered audit-log-path via static manifest (raw scan)")
        return m.group(1)
    return None


def discover_audit_log_path(configured_path: str | None) -> str:
    """Resolve the audit log path or raise AuditLogNotFoundError.

    `configured_path` should be `Config.audit_log_path` — explicit
    configuration always takes priority over auto-discovery.
    """
    if configured_path:
        logger.info("Using configured AUDIT_LOG_PATH=%s", configured_path)
        return configured_path

    found = _scan_proc_for_apiserver()
    if found:
        return found

    found = _scan_static_manifest()
    if found:
        return found

    raise AuditLogNotFoundError(
        "Could not discover the Kubernetes audit log path. Checked: "
        "(1) AUDIT_LOG_PATH env var, (2) /proc/<pid>/cmdline for a running "
        "kube-apiserver, (3) /etc/kubernetes/manifests/kube-apiserver.yaml. "
        "This usually means the collector cannot see the control-plane "
        "process/filesystem from its current container. Run on the "
        "control-plane node, mount the audit-log directory into the "
        "Guardian container, or inspect the apiserver Pod yourself with "
        "`kubectl -n kube-system get pod -l component=kube-apiserver -o "
        "yaml | grep audit-log-path` and set AUDIT_LOG_PATH explicitly. "
        "Refusing to guess a default path."
    )
