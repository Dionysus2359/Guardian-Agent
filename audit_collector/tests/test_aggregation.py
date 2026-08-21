import unittest

from collector.aggregator import apply_events
from collector.models import AuditEvent
from collector.output import to_serializable


def _event(**kwargs):
    defaults = dict(
        service_account="backup-sa",
        namespace_identity="prod",
        resource_namespace="prod",
        api_group="",
        resource="secrets",
        verb="get",
        timestamp="2026-07-29T10:14:02Z",
        response_code=200,
    )
    defaults.update(kwargs)
    return AuditEvent(**defaults)


class TestPermissionIdentity(unittest.TestCase):
    def test_different_resources_same_verb_are_distinct_permissions(self):
        aggregate = {}
        apply_events(
            aggregate,
            [
                _event(resource="pods", verb="get"),
                _event(resource="secrets", verb="get"),
                _event(resource="configmaps", verb="get"),
            ],
        )
        record = aggregate[("prod", "backup-sa")]
        self.assertEqual(len(record["permissions_used"]), 3)

    def test_different_verbs_same_resource_are_distinct_permissions(self):
        aggregate = {}
        apply_events(
            aggregate,
            [
                _event(resource="pods", verb="get"),
                _event(resource="pods", verb="list"),
                _event(resource="pods", verb="delete"),
            ],
        )
        record = aggregate[("prod", "backup-sa")]
        self.assertEqual(len(record["permissions_used"]), 3)

    def test_multiple_events_same_permission_aggregate_count(self):
        aggregate = {}
        apply_events(aggregate, [_event() for _ in range(5000)])
        record = aggregate[("prod", "backup-sa")]
        entry = next(iter(record["permissions_used"].values()))
        self.assertEqual(entry["count"], 5000)


class TestLastSeenAndFirstSeen(unittest.TestCase):
    def test_last_seen_tracks_most_recent_timestamp(self):
        aggregate = {}
        apply_events(
            aggregate,
            [
                _event(timestamp="2026-07-01T10:00:00Z"),
                _event(timestamp="2026-07-29T10:14:02Z"),
                _event(timestamp="2026-07-15T00:00:00Z"),
            ],
        )
        entry = next(iter(aggregate[("prod", "backup-sa")]["permissions_used"].values()))
        self.assertEqual(entry["last_seen"], "2026-07-29T10:14:02Z")
        self.assertEqual(entry["first_seen"], "2026-07-01T10:00:00Z")


class TestMultipleServiceAccounts(unittest.TestCase):
    def test_different_service_accounts_kept_separate(self):
        aggregate = {}
        apply_events(
            aggregate,
            [
                _event(service_account="backup-sa", namespace_identity="prod"),
                _event(service_account="ci-runner", namespace_identity="ci"),
            ],
        )
        self.assertIn(("prod", "backup-sa"), aggregate)
        self.assertIn(("ci", "ci-runner"), aggregate)
        self.assertEqual(len(aggregate), 2)


class TestQuarterlyAggregation(unittest.TestCase):
    def test_quarter_derived_from_event_timestamp_not_scan_time(self):
        aggregate = {}
        apply_events(aggregate, [_event(timestamp="2026-07-29T10:14:02Z", resource="pods", verb="get")])
        record = aggregate[("prod", "backup-sa")]
        self.assertIn("2026-Q3", record["quarterly_usage"])
        q = record["quarterly_usage"]["2026-Q3"]
        self.assertEqual(q["verb_counts"]["get"], 1)
        self.assertEqual(q["resources_touched"]["pods"], 1)

    def test_quarter_end_date_is_last_day_of_quarter(self):
        aggregate = {}
        apply_events(aggregate, [_event(timestamp="2026-07-29T10:14:02Z")])
        q = aggregate[("prod", "backup-sa")]["quarterly_usage"]["2026-Q3"]
        self.assertEqual(q["start_date"], "2026-07-01")
        self.assertEqual(q["end_date"], "2026-09-30")

    def test_q4_end_date_rolls_into_next_year_correctly(self):
        aggregate = {}
        apply_events(aggregate, [_event(timestamp="2026-11-15T00:00:00Z")])
        q = aggregate[("prod", "backup-sa")]["quarterly_usage"]["2026-Q4"]
        self.assertEqual(q["start_date"], "2026-10-01")
        self.assertEqual(q["end_date"], "2026-12-31")

    def test_events_split_across_quarters(self):
        aggregate = {}
        apply_events(
            aggregate,
            [
                _event(timestamp="2026-03-31T23:59:00Z"),  # Q1
                _event(timestamp="2026-04-01T00:00:01Z"),  # Q2
            ],
        )
        record = aggregate[("prod", "backup-sa")]
        self.assertIn("2026-Q1", record["quarterly_usage"])
        self.assertIn("2026-Q2", record["quarterly_usage"])


class TestSpecialOperationsSeparated(unittest.TestCase):
    def test_watch_kept_out_of_permissions_used(self):
        aggregate = {}
        apply_events(aggregate, [_event(verb="watch", resource="pods")])
        record = aggregate[("prod", "backup-sa")]
        self.assertEqual(len(record["permissions_used"]), 0)
        self.assertIn("watch", record["special_operations"])


class TestSerialization(unittest.TestCase):
    def test_to_serializable_produces_expected_schema_keys(self):
        aggregate = {}
        apply_events(aggregate, [_event()])
        payload = to_serializable(aggregate)
        self.assertIn("generated_at", payload)
        self.assertIn("time_window", payload)
        self.assertIn("service_accounts", payload)
        sa = payload["service_accounts"][0]
        self.assertEqual(sa["service_account"], "backup-sa")
        self.assertEqual(sa["namespace"], "prod")
        self.assertIn("permissions_used", sa)
        self.assertIn("quarterly_usage", sa)


if __name__ == "__main__":
    unittest.main()
