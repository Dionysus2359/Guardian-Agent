"""Parsing and filtering of raw Kubernetes audit events.

One JSON object per line is expected (standard `--audit-log-path` format).
Every field access here is defensive: the spec (section 2) explicitly
warns that optional fields (namespace, apiGroup, requestObject,
responseStatus, ...) may be absent on any given event.
"""
from __future__ import annotations

import json
import logging
import re
from enum import Enum, auto

from .models import AuditEvent

logger = logging.getLogger("guardian.collector.parser")

_SA_USERNAME_RE = re.compile(r"^system:serviceaccount:(?P<namespace>[^:]+):(?P<name>[^:]+)$")


class SkipReason(Enum):
    MALFORMED_JSON = auto()
    INCOMPLETE_STAGE = auto()
    FAILED_REQUEST = auto()
    NOT_SERVICE_ACCOUNT = auto()
    NAMESPACE_FILTERED = auto()


class ParseResult:
    """Either a usable AuditEvent, or a reason it was skipped."""

    __slots__ = ("event", "skip_reason", "raw_error")

    def __init__(
        self,
        event: AuditEvent | None = None,
        skip_reason: SkipReason | None = None,
        raw_error: str | None = None,
    ) -> None:
        self.event = event
        self.skip_reason = skip_reason
        self.raw_error = raw_error

    @property
    def ok(self) -> bool:
        return self.event is not None


def _is_success(response_status: dict | None) -> tuple[bool, int | None]:
    """200 <= code < 300. Never a bare == 200 check (spec section 7)."""
    if not response_status:
        return False, None
    code = response_status.get("code")
    if not isinstance(code, int):
        return False, None
    return 200 <= code < 300, code


def _extract_service_account(username: str | None) -> tuple[str, str] | None:
    """Returns (namespace, sa_name) or None if not a ServiceAccount identity.

    Deliberately excludes system:apiserver, system:node:*, human/admin
    users, etc. (spec section 8).
    """
    if not username:
        return None
    m = _SA_USERNAME_RE.match(username)
    if not m:
        return None
    return m.group("namespace"), m.group("name")


def parse_line(
    raw_line: str,
    *,
    namespace_filter,
) -> ParseResult:
    """Parse+filter a single raw audit-log line.

    `namespace_filter` is a callable `(namespace: str | None) -> bool`
    (typically `Config.matches_namespace`) applied to the ServiceAccount's
    OWN namespace (from its username), not the object's namespace — a
    ServiceAccount always belongs to exactly one namespace, whereas the
    object it acted on may be cluster-scoped.
    """
    line = raw_line.strip()
    if not line:
        return ParseResult(skip_reason=SkipReason.MALFORMED_JSON, raw_error="empty line")

    try:
        event = json.loads(line)
    except json.JSONDecodeError as exc:
        return ParseResult(
            skip_reason=SkipReason.MALFORMED_JSON,
            raw_error=f"{exc} | line_prefix={line[:120]!r}",
        )

    if not isinstance(event, dict):
        return ParseResult(
            skip_reason=SkipReason.MALFORMED_JSON,
            raw_error=f"top-level JSON was not an object: {type(event).__name__}",
        )

    # Only fully completed requests count as evidence of actual usage.
    if event.get("stage") != "ResponseComplete":
        return ParseResult(skip_reason=SkipReason.INCOMPLETE_STAGE)

    success, code = _is_success(event.get("responseStatus"))
    if not success:
        return ParseResult(skip_reason=SkipReason.FAILED_REQUEST)

    user = event.get("user") or {}
    sa = _extract_service_account(user.get("username"))
    if sa is None:
        return ParseResult(skip_reason=SkipReason.NOT_SERVICE_ACCOUNT)
    sa_namespace, sa_name = sa

    if not namespace_filter(sa_namespace):
        return ParseResult(skip_reason=SkipReason.NAMESPACE_FILTERED)

    object_ref = event.get("objectRef") or {}
    resource = object_ref.get("resource")
    if not resource:
        # Without a resource we cannot form a meaningful PermissionKey.
        return ParseResult(
            skip_reason=SkipReason.MALFORMED_JSON,
            raw_error="missing objectRef.resource on an otherwise valid event",
        )

    api_group = object_ref.get("apiGroup") or ""  # "" = core group; never invented
    resource_namespace = object_ref.get("namespace")  # None => cluster-scoped, never "default"
    verb = event.get("verb") or "unknown"
    timestamp = event.get("requestReceivedTimestamp") or event.get("stageTimestamp")
    if not timestamp:
        return ParseResult(
            skip_reason=SkipReason.MALFORMED_JSON,
            raw_error="missing both requestReceivedTimestamp and stageTimestamp",
        )

    parsed = AuditEvent(
        service_account=sa_name,
        namespace_identity=sa_namespace,
        resource_namespace=resource_namespace,
        api_group=api_group,
        resource=resource,
        verb=verb,
        timestamp=timestamp,
        response_code=code if code is not None else 0,
    )
    return ParseResult(event=parsed)
