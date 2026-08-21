"""Data models for the Guardian Audit Collector.

Deliberately minimal: we only ever hold the metadata needed for
permission-usage analysis. We never carry requestObject/responseObject/
secret contents (spec section 20).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Kubernetes verbs that don't map cleanly onto a single normal RBAC rule
# check. We still record these (spec section 21 forbids silently dropping
# or relabeling them) but callers can identify them via `is_special`.
SPECIAL_VERBS = frozenset({"watch", "proxy", "connect"})


@dataclass(frozen=True)
class PermissionKey:
    """Identity of a permission: (apiGroup, resource, verb).

    Never identify a permission by verb alone — "get pods" and
    "get secrets" are different permissions (spec section 9).
    """

    api_group: str  # "" for the core/legacy API group, never omitted/invented
    resource: str
    verb: str

    @property
    def is_special(self) -> bool:
        return self.verb in SPECIAL_VERBS

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.api_group, self.resource, self.verb)


@dataclass
class AuditEvent:
    """A parsed, filtered-down Kubernetes audit event.

    Only ever constructed for events that already passed the
    ResponseComplete + success-status + ServiceAccount-user filters.
    """

    service_account: str
    namespace_identity: str  # namespace the ServiceAccount itself belongs to
    resource_namespace: str | None  # namespace of the object acted upon (None = cluster-scoped)
    api_group: str
    resource: str
    verb: str
    timestamp: str  # ISO-8601 UTC, from requestReceivedTimestamp (falls back to stageTimestamp)
    response_code: int

    @property
    def permission_key(self) -> PermissionKey:
        return PermissionKey(self.api_group, self.resource, self.verb)


@dataclass
class ScanStats:
    """Per-cycle counters for operational logging (spec section 23)."""

    events_scanned: int = 0
    service_account_events: int = 0
    ignored_non_service_account: int = 0
    failed_events_ignored: int = 0
    malformed_events: int = 0
    skipped_incomplete_stage: int = 0
    filtered_by_namespace: int = 0
    new_events_processed: int = 0
    service_accounts_touched: set[str] = field(default_factory=set)
