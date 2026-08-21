"""Guardian Node : Kubernetes Audit Log & Data Collector.

This package is an evidence-collection component only. It does not
make security decisions, does not modify RBAC, does not generate
RBAC YAML, and does not call an LLM. See README.md.
"""

__all__ = [
    "config",
    "models",
    "parser",
    "state",
    "aggregator",
    "output",
    "discover",
    "audit_collector",
]
