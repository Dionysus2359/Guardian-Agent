"""Node 1 / Agent 1: Audit & Data Collector — orchestration entrypoint.

This module wires together discover -> state -> parser -> aggregator ->
output into a single scan cycle, and a continuous polling loop around
that cycle. It is designed to be imported and called by another Guardian
component just as easily as run standalone:

    from collector.audit_collector import run_once, run_forever
    run_once()            # single scan, useful for cron/CI/tests
    run_forever()          # continuous SCAN_INTERVAL_SECONDS polling loop

Guardian architecture boundary (spec section 28): this component NEVER
decides that a permission is excessive or should be revoked, never
touches RBAC, never generates YAML, and never calls an LLM. It answers
exactly one question: what permissions did each ServiceAccount actually
use, how often, and when was each last observed.
"""
from __future__ import annotations

import logging
import os
import signal
import time

from . import aggregator, output
from .config import Config, load_config
from .discover import AuditLogNotFoundError, discover_audit_log_path
from .models import ScanStats
from .parser import SkipReason, parse_line
from .state import ScannerState

logger = logging.getLogger("guardian.collector")


def _configure_logging(config: Config) -> logging.Logger:
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    err_logger = logging.getLogger("guardian.collector.errors")
    if not err_logger.handlers:
        os.makedirs(os.path.dirname(config.error_log_path) or ".", exist_ok=True)
        file_handler = logging.FileHandler(config.error_log_path)
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        err_logger.addHandler(file_handler)
        err_logger.setLevel(logging.INFO)
        err_logger.propagate = False
    return err_logger


def run_once(config: Config | None = None) -> ScanStats:
    """Execute a single scan cycle. Returns the cycle's ScanStats.

    Safe to call repeatedly/idempotently: state and aggregate are both
    loaded from disk at the start and persisted atomically at the end,
    so a restart mid-cycle cannot double-count or corrupt output
    (spec sections 17, 18, 22).
    """
    config = config or load_config()
    config.ensure_parent_dirs()
    err_logger = _configure_logging(config)

    try:
        audit_log_path = discover_audit_log_path(config.audit_log_path)
    except AuditLogNotFoundError as exc:
        logger.error(str(exc))
        raise

    logger.info("Audit log discovered: %s", audit_log_path)
    logger.info("Starting collector scan (target_namespace=%s)...", config.target_namespace)

    stats = ScanStats()
    scanner_state = ScannerState.load(config.state_path)

    try:
        file_size = os.path.getsize(audit_log_path)
        file_inode = os.stat(audit_log_path).st_ino
    except OSError as exc:
        logger.error("Could not stat audit log at %s: %s", audit_log_path, exc)
        raise

    reset = scanner_state.reconcile_with_file(file_size, file_inode)
    if reset:
        logger.warning("Scanner offset was reset due to rotation/truncation")

    aggregate = output.load_aggregate(config.output_path)
    events_to_apply = []

    with open(audit_log_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(scanner_state.offset)
        for raw_line in f:
            stats.events_scanned += 1
            result = parse_line(raw_line, namespace_filter=config.matches_namespace)

            if result.ok:
                stats.service_account_events += 1
                events_to_apply.append(result.event)
                continue

            reason = result.skip_reason
            if reason is SkipReason.MALFORMED_JSON:
                stats.malformed_events += 1
                err_logger.info("MALFORMED_EVENT: %s", result.raw_error)
            elif reason is SkipReason.INCOMPLETE_STAGE:
                stats.skipped_incomplete_stage += 1
            elif reason is SkipReason.FAILED_REQUEST:
                stats.failed_events_ignored += 1
            elif reason is SkipReason.NOT_SERVICE_ACCOUNT:
                stats.ignored_non_service_account += 1
            elif reason is SkipReason.NAMESPACE_FILTERED:
                stats.filtered_by_namespace += 1

        scanner_state.offset = f.tell()

    aggregator.apply_events(aggregate, events_to_apply, stats=stats)

    window_start = None
    if aggregate:
        # Earliest first_seen across all permissions, if we want a real
        # window start; kept simple/best-effort for the PoC.
        try:
            window_start = min(
                pu["first_seen"]
                for record in aggregate.values()
                for pu in record["permissions_used"].values()
            )
        except ValueError:
            window_start = None

    payload = output.to_serializable(aggregate, window_start=window_start)
    output.write_atomic(config.output_path, payload)
    scanner_state.save(config.state_path)

    logger.info("Events scanned: %d", stats.events_scanned)
    logger.info("ServiceAccount events: %d", stats.service_account_events)
    logger.info("Ignored non-ServiceAccount events: %d", stats.ignored_non_service_account)
    logger.info("Failed events ignored: %d", stats.failed_events_ignored)
    logger.info("Skipped (incomplete stage) events: %d", stats.skipped_incomplete_stage)
    logger.info("Filtered by namespace: %d", stats.filtered_by_namespace)
    logger.info("Malformed events: %d", stats.malformed_events)
    logger.info("New events processed: %d", stats.new_events_processed)
    logger.info("ServiceAccounts touched this cycle: %d", len(stats.service_accounts_touched))
    logger.info("Output updated: %s", config.output_path)

    return stats


def run_forever(config: Config | None = None) -> None:
    """Continuous polling loop, per SCAN_INTERVAL_SECONDS."""
    config = config or load_config()
    _configure_logging(config)

    stop = {"flag": False}

    def _handle_signal(signum, _frame):
        logger.info("Received signal %s — shutting down after current cycle", signum)
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info(
        "Starting continuous collector loop (interval=%ds)", config.scan_interval_seconds
    )
    while not stop["flag"]:
        try:
            run_once(config)
        except AuditLogNotFoundError:
            logger.error(
                "Audit log unavailable this cycle — will retry in %ds",
                config.scan_interval_seconds,
            )
        except Exception:  # noqa: BLE001 - a single bad cycle must not kill the loop
            logger.exception("Unexpected error during scan cycle — will retry next interval")
        for _ in range(config.scan_interval_seconds):
            if stop["flag"]:
                break
            time.sleep(1)


if __name__ == "__main__":
    run_forever()
