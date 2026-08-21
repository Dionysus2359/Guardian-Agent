import unittest

from collector.config import Config
from collector.parser import SkipReason, parse_line
from tests.fixtures import make_event


class TestTargetNamespaceFiltering(unittest.TestCase):
    def test_wildcard_matches_everything(self):
        config = Config(target_namespace="*")
        self.assertTrue(config.matches_namespace("prod"))
        self.assertTrue(config.matches_namespace("kube-system"))
        self.assertTrue(config.matches_namespace(None))

    def test_specific_namespace_only_matches_itself(self):
        config = Config(target_namespace="prod")
        self.assertTrue(config.matches_namespace("prod"))
        self.assertFalse(config.matches_namespace("staging"))

    def test_namespace_filter_applied_during_parse(self):
        config = Config(target_namespace="staging")
        line = make_event(username="system:serviceaccount:prod:backup-sa")
        result = parse_line(line, namespace_filter=config.matches_namespace)
        self.assertFalse(result.ok)
        self.assertEqual(result.skip_reason, SkipReason.NAMESPACE_FILTERED)

    def test_default_config_does_not_hardcode_default_namespace(self):
        # Regression guard for spec section 12: default must not silently
        # restrict collection to the "default" namespace.
        config = Config()
        self.assertEqual(config.target_namespace, "*")


class TestSpecialVerbs(unittest.TestCase):
    def test_watch_is_parsed_but_flagged_special(self):
        line = make_event(verb="watch", resource="pods")
        result = parse_line(line, namespace_filter=lambda ns: True)
        self.assertTrue(result.ok)
        self.assertTrue(result.event.permission_key.is_special)

    def test_proxy_is_parsed_but_flagged_special(self):
        line = make_event(verb="proxy", resource="services")
        result = parse_line(line, namespace_filter=lambda ns: True)
        self.assertTrue(result.ok)
        self.assertTrue(result.event.permission_key.is_special)

    def test_connect_is_parsed_but_flagged_special(self):
        line = make_event(verb="connect", resource="pods")
        result = parse_line(line, namespace_filter=lambda ns: True)
        self.assertTrue(result.ok)
        self.assertTrue(result.event.permission_key.is_special)

    def test_get_is_not_special(self):
        line = make_event(verb="get", resource="pods")
        result = parse_line(line, namespace_filter=lambda ns: True)
        self.assertFalse(result.event.permission_key.is_special)

    def test_verb_is_never_silently_relabeled(self):
        line = make_event(verb="watch", resource="pods")
        result = parse_line(line, namespace_filter=lambda ns: True)
        self.assertEqual(result.event.verb, "watch")


if __name__ == "__main__":
    unittest.main()
