"""Reusable sample Kubernetes audit event builders for tests."""
import json


def make_event(
    *,
    verb="get",
    resource="pods",
    api_group=None,
    namespace="prod",
    username="system:serviceaccount:prod:backup-sa",
    code=200,
    stage="ResponseComplete",
    timestamp="2026-07-29T10:14:02Z",
    include_object_ref_namespace=True,
    include_api_group=True,
    include_response_status=True,
    extra_object_ref=None,
) -> str:
    object_ref = {"resource": resource}
    if include_object_ref_namespace and namespace is not None:
        object_ref["namespace"] = namespace
    if include_api_group and api_group is not None:
        object_ref["apiGroup"] = api_group
    if extra_object_ref:
        object_ref.update(extra_object_ref)

    event = {
        "apiVersion": "audit.k8s.io/v1",
        "auditID": "38337641-0965-4577-bc2a-62f6f700b09b",
        "kind": "Event",
        "level": "Request",
        "objectRef": object_ref,
        "requestReceivedTimestamp": timestamp,
        "stage": stage,
        "user": {"username": username},
        "verb": verb,
    }
    if include_response_status:
        event["responseStatus"] = {"code": code}
    return json.dumps(event)
