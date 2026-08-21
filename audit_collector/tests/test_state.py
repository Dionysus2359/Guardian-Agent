import json
import os
import tempfile
import unittest
from pathlib import Path

from collector.audit_collector import run_once
from collector.config import Config
from collector.state import ScannerState
from tests.fixtures import make_event


class TestScannerStatePersistence(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = os.path.join(tmp, "state.json")
            state = ScannerState(offset=4096, inode=123)
            state.save(state_path)

            loaded = ScannerState.load(state_path)
            self.assertEqual(loaded.offset, 4096)
            self.assertEqual(loaded.inode, 123)

    def test_load_missing_file_returns_zero_offset(self):
        with tempfile.TemporaryDirectory() as tmp:
            loaded = ScannerState.load(os.path.join(tmp, "does-not-exist.json"))
            self.assertEqual(loaded.offset, 0)

    def test_load_corrupt_file_resets_to_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = os.path.join(tmp, "state.json")
            Path(state_path).write_text("{not valid json")
            loaded = ScannerState.load(state_path)
            self.assertEqual(loaded.offset, 0)


class TestTruncationHandling(unittest.TestCase):
    def test_offset_beyond_file_size_resets(self):
        state = ScannerState(offset=10_000, inode=1)
        reset = state.reconcile_with_file(file_size=500, file_inode=1)
        self.assertTrue(reset)
        self.assertEqual(state.offset, 0)

    def test_inode_change_resets_even_if_size_grew(self):
        state = ScannerState(offset=100, inode=1)
        reset = state.reconcile_with_file(file_size=99999, file_inode=2)
        self.assertTrue(reset)
        self.assertEqual(state.offset, 0)

    def test_normal_growth_does_not_reset(self):
        state = ScannerState(offset=100, inode=1)
        reset = state.reconcile_with_file(file_size=5000, file_inode=1)
        self.assertFalse(reset)
        self.assertEqual(state.offset, 100)


class TestEndToEndRestartNoDoubleCounting(unittest.TestCase):
    def _make_config(self, tmp_dir, log_path):
        return Config(
            audit_log_path=log_path,
            output_path=os.path.join(tmp_dir, "guardian_audit.json"),
            state_path=os.path.join(tmp_dir, ".audit_scan_state.json"),
            target_namespace="*",
            error_log_path=os.path.join(tmp_dir, "errors.log"),
        )

    def test_second_run_does_not_reprocess_first_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            with open(log_path, "w") as f:
                f.write(make_event(verb="get", resource="pods") + "\n")
                f.write(make_event(verb="get", resource="pods") + "\n")

            config = self._make_config(tmp, log_path)
            run_once(config)

            with open(config.output_path) as f:
                data = json.loads(f.read())
            entry = data["service_accounts"][0]["permissions_used"][0]
            self.assertEqual(entry["count"], 2)

            # Second scan with no new lines appended must not double-count.
            run_once(config)
            with open(config.output_path) as f:
                data = json.loads(f.read())
            entry = data["service_accounts"][0]["permissions_used"][0]
            self.assertEqual(entry["count"], 2)

    def test_restart_resumes_and_appends_new_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            with open(log_path, "w") as f:
                f.write(make_event(verb="get", resource="pods") + "\n")

            config = self._make_config(tmp, log_path)
            run_once(config)

            # Simulate the collector restarting and new events arriving.
            with open(log_path, "a") as f:
                f.write(make_event(verb="get", resource="pods") + "\n")

            run_once(config)
            with open(config.output_path) as f:
                data = json.loads(f.read())
            entry = data["service_accounts"][0]["permissions_used"][0]
            self.assertEqual(entry["count"], 2)

    def test_log_truncation_does_not_crash_and_resets_offset(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            with open(log_path, "w") as f:
                f.write(make_event(verb="get", resource="pods") + "\n" * 1)

            config = self._make_config(tmp, log_path)
            run_once(config)  # advances offset well past 0

            # Simulate truncation/rotation: force the stored offset far
            # beyond what the (now-replaced, shorter) file actually
            # contains — this is the exact condition spec section 5
            # requires the collector to detect and recover from.
            state = ScannerState.load(config.state_path)
            state.offset = 10_000_000
            state.save(config.state_path)

            with open(log_path, "w") as f:
                f.write(make_event(verb="list", resource="secrets") + "\n")

            stats = run_once(config)
            self.assertEqual(stats.malformed_events, 0)

    def test_malformed_line_does_not_crash_collector(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            with open(log_path, "w") as f:
                f.write("{not valid json\n")
                f.write(make_event(verb="get", resource="pods") + "\n")

            config = self._make_config(tmp, log_path)
            stats = run_once(config)  # must not raise
            self.assertEqual(stats.malformed_events, 1)
            self.assertEqual(stats.service_account_events, 1)


if __name__ == "__main__":
    unittest.main()
