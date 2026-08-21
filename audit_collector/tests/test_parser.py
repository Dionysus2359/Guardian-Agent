import unittest

from collector.parser import SkipReason, parse_line
from tests.fixtures import make_event

ALL_NAMESPACES = lambda ns: True  # noqa: E731


class TestParserSuccessfulEvents(unittest.TestCase):
    def test_successful_get(self):
        line = make_event(verb="get", resource="pods", code=200)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)
        self.assertEqual(result.event.verb, "get")
        self.assertEqual(result.event.resource, "pods")

    def test_successful_list(self):
        line = make_event(verb="list", resource="pods", code=200)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)
        self.assertEqual(result.event.verb, "list")

    def test_successful_create_201(self):
        line = make_event(verb="create", resource="pods", code=201)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)
        self.assertEqual(result.event.response_code, 201)

    def test_successful_delete_204(self):
        line = make_event(verb="delete", resource="pods", code=204)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)
        self.assertEqual(result.event.response_code, 204)

    def test_2xx_boundary_299_accepted(self):
        line = make_event(verb="get", resource="pods", code=299)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)

    def test_300_rejected(self):
        line = make_event(verb="get", resource="pods", code=300)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertFalse(result.ok)
        self.assertEqual(result.skip_reason, SkipReason.FAILED_REQUEST)


class TestParserFailuresAndIdentity(unittest.TestCase):
    def test_failed_request(self):
        line = make_event(verb="get", resource="secrets", code=403)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertFalse(result.ok)
        self.assertEqual(result.skip_reason, SkipReason.FAILED_REQUEST)

    def test_non_service_account_user_ignored(self):
        line = make_event(username="system:apiserver", code=200)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertFalse(result.ok)
        self.assertEqual(result.skip_reason, SkipReason.NOT_SERVICE_ACCOUNT)

    def test_admin_user_ignored(self):
        line = make_event(username="admin", code=200)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertEqual(result.skip_reason, SkipReason.NOT_SERVICE_ACCOUNT)

    def test_node_user_ignored(self):
        line = make_event(username="system:node:worker-1", code=200)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertEqual(result.skip_reason, SkipReason.NOT_SERVICE_ACCOUNT)

    def test_service_account_identity_extracted(self):
        line = make_event(username="system:serviceaccount:prod:backup-sa", code=200)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)
        self.assertEqual(result.event.service_account, "backup-sa")
        self.assertEqual(result.event.namespace_identity, "prod")


class TestParserNamespaceHandling(unittest.TestCase):
    def test_namespaced_resource(self):
        line = make_event(resource="secrets", namespace="prod")
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)
        self.assertEqual(result.event.resource_namespace, "prod")

    def test_cluster_scoped_resource_has_null_namespace(self):
        line = make_event(
            resource="clusterroles", include_object_ref_namespace=False
        )
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)
        self.assertIsNone(result.event.resource_namespace)

    def test_missing_object_ref_namespace_is_not_default(self):
        line = make_event(resource="nodes", include_object_ref_namespace=False)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)
        self.assertNotEqual(result.event.resource_namespace, "default")
        self.assertIsNone(result.event.resource_namespace)


class TestParserApiGroupHandling(unittest.TestCase):
    def test_missing_api_group_normalizes_to_empty_string(self):
        line = make_event(resource="pods", include_api_group=False)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)
        self.assertEqual(result.event.api_group, "")

    def test_present_api_group_preserved(self):
        line = make_event(resource="deployments", api_group="apps")
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertTrue(result.ok)
        self.assertEqual(result.event.api_group, "apps")


class TestParserMissingOptionalFields(unittest.TestCase):
    def test_missing_response_status_is_failure(self):
        line = make_event(include_response_status=False)
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertFalse(result.ok)
        self.assertEqual(result.skip_reason, SkipReason.FAILED_REQUEST)

    def test_non_response_complete_stage_skipped(self):
        line = make_event(stage="ResponseStarted")
        result = parse_line(line, namespace_filter=ALL_NAMESPACES)
        self.assertFalse(result.ok)
        self.assertEqual(result.skip_reason, SkipReason.INCOMPLETE_STAGE)


class TestParserMalformedJSON(unittest.TestCase):
    def test_malformed_json_does_not_raise(self):
        result = parse_line("{not valid json", namespace_filter=ALL_NAMESPACES)
        self.assertFalse(result.ok)
        self.assertEqual(result.skip_reason, SkipReason.MALFORMED_JSON)
        self.assertIsNotNone(result.raw_error)

    def test_empty_line_does_not_raise(self):
        result = parse_line("   \n", namespace_filter=ALL_NAMESPACES)
        self.assertFalse(result.ok)
        self.assertEqual(result.skip_reason, SkipReason.MALFORMED_JSON)

    def test_non_object_json_does_not_raise(self):
        result = parse_line("[1, 2, 3]", namespace_filter=ALL_NAMESPACES)
        self.assertFalse(result.ok)
        self.assertEqual(result.skip_reason, SkipReason.MALFORMED_JSON)


if __name__ == "__main__":
    unittest.main()
