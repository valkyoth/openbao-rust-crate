#!/usr/bin/python3 -EsSB
"""Version, protocol, partition recovery and cleanup checks for the patch runner."""

import base64
from contextlib import ExitStack, redirect_stdout
import io
import unittest
from unittest.mock import MagicMock, patch

import openbao_2_7_1_consistency as fixture


class ConsistencyTests(unittest.TestCase):
    def health(self, version="2.7.1", cluster="fixture", standby=True):
        return (429 if standby else 200,
                {"version": version, "cluster_id": cluster, "initialized": True,
                 "sealed": False, "standby": standby}, None, None)

    def test_ready_cluster_requires_exact_version_and_shared_identity(self):
        good = [self.health(standby=False), self.health(), self.health()]
        for version in ("2.7.0", "2.7.2", "2.7.1-beta1"):
            with self.subTest(version=version), patch.object(fixture.protocol, "request", side_effect=
                 [good[0], self.health(version=version), good[2]]), self.assertRaises(fixture.harness.HarnessError):
                fixture.ready_cluster(["one", "two", "three"], None)
        with patch.object(fixture.protocol, "request", side_effect=good):
            self.assertEqual(fixture.ready_cluster(["one", "two", "three"], None), (0, "fixture"))
        with patch.object(fixture.protocol, "request", side_effect=[good[0], self.health(cluster="different"), good[2]]), \
             self.assertRaises(fixture.harness.HarnessError):
            fixture.ready_cluster(["one", "two", "three"], None)

    def test_duplicate_addresses_rejected(self):
        with self.assertRaises(fixture.harness.HarnessError):
            fixture.ready_cluster(["one"] * 3, None)

    def run_probe(self, bad_status=False, bad_recovery=False):
        def read(marker, version):
            return 200, {"data": {"data": {"marker": marker}, "metadata": {"version": version}}}, None, None
        initial, lagged = read("initial", 1), read("lagged", 2)
        index = base64.b64encode(fixture.base.canonical_json({"cluster": "fixture", "value": "10"})).decode("ascii")
        written = lambda version: (200, {"data": {"version": version}}, index, None)
        rejected = (429, {}, None, "1")
        responses = [
            (200, {"data": {"config": {"servers": [{"voter": True, "node_id": f"fixture-{i}"} for i in range(3)]}}}, None, None),
            (204, {}, None, None), written(1), initial, initial, rejected, rejected, initial, initial,
            (400, {}, None, None), rejected, initial, written(2), initial,
            (200, {}, None, None) if bad_status else rejected, rejected, rejected, lagged,
        ]
        partition = MagicMock()
        pending = MagicMock()
        pending.done.return_value = False
        pending.result.return_value = (429, {}, None, None) if bad_recovery else lagged
        pool = MagicMock()
        pool.submit.return_value = pending
        with redirect_stdout(io.StringIO()), \
             patch.object(fixture, "ready_cluster", return_value=(0, "fixture")), \
             patch.object(fixture.protocol, "request", side_effect=responses) as request, \
             patch.object(fixture.lag, "RaftPartition") as partition_factory, \
             patch.object(fixture, "ThreadPoolExecutor") as pool_factory, \
             patch.object(fixture.time, "sleep"), \
             patch.object(fixture.time, "monotonic", side_effect=[0, 0.25, 1, 1.25]):
            partition_factory.return_value.__enter__.return_value = partition
            pool_factory.return_value.__enter__.return_value = pool
            args = (["leader", "follower", "other"], ["recovery-a", "recovery-b", "recovery-c"],
                    ["one", "two", "three"], None, "disposable", "podman", "a" * 32, {})
            if bad_status or bad_recovery:
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.probe(*args)
            else:
                fixture.probe(*args)
                self.assertEqual(request.call_count, len(responses))
                self.assertEqual(pool.submit.call_args.args[1], "recovery-b")
                self.assertEqual(pool.submit.call_args.kwargs["policies"], ("await-state", "fail"))
                self.assertEqual(pool.submit.call_args.kwargs["timeout"], 15)
                partition.restore.assert_called_once()
            partition_factory.return_value.__exit__.assert_called_once()

    def test_full_protocol_assertions(self):
        self.run_probe()

    def test_accepted_stale_index_cannot_pass(self):
        self.run_probe(bad_status=True)

    def test_failed_await_cannot_be_retried_into_success(self):
        self.run_probe(bad_recovery=True)

    def run_mocked(self, failure=None):
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(io.StringIO()))

            def mock(obj, name, **options):
                return stack.enter_context(patch.object(obj, name, **options))

            mock(fixture.os, "geteuid", return_value=0)
            mock(fixture, "input_hashes", side_effect=[{"source": "before"},
                 {"source": "changed" if failure == "inputs" else "before"}])
            mock(fixture.image_evidence, "verify")
            mock(fixture.patch, "verify_signature")
            mock(fixture.tls.evidence_tools, "protected_path", side_effect=lambda path: path)
            mock(fixture.harness, "generate_tls", side_effect=lambda root, *_: (root / "tls", root / "ca"))
            mock(fixture.harness, "inspect_image", return_value="pinned-image")
            mock(fixture.harness, "run_bounded", return_value=b"{}")
            mock(fixture.protocol, "node_addresses", return_value=["10.99.0.10", "10.99.0.11", "10.99.0.12"])
            mock(fixture.lag, "write_config", side_effect=lambda root, *_: root / "node.hcl")
            limits = mock(fixture.base, "validate_container_resource_config")
            network = mock(fixture.tls, "verify_network")
            mock(fixture.harness, "parse_port", side_effect=range(12000, 12006))
            health = mock(fixture.harness, "wait_for_exact_version")
            rejection = mock(fixture.tls, "probe_tls")
            mock(fixture.protocol, "initialize_cluster", return_value="disposable-token")
            mock(fixture, "probe", side_effect=fixture.harness.HarnessError("failed") if failure == "probe" else None)
            mock(fixture.harness, "cleanup_private_files", return_value=True)
            remove = mock(fixture.harness, "remove_owned_resource", side_effect=OSError() if failure == "cleanup" else None)
            if failure:
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.run()
            else:
                report = fixture.run()
                self.assertEqual(report["version"], "2.7.1")
                self.assertEqual(report["nodes"], 3)
                self.assertEqual(report["scope"], "controlled-lag-server-protocol-only")
                self.assertFalse(report["routable"])
                self.assertFalse(report["sdk_live_verified"])
                self.assertEqual(limits.call_count, 3)
                self.assertEqual(network.call_count, 3)
                self.assertEqual(rejection.call_count, 6)
                self.assertEqual([call.args[2] for call in health.call_args_list], ["2.7.1"] * 6)
            self.assertEqual([call.args[1] for call in remove.call_args_list], ["container"] * 3 + ["network"])
            self.assertEqual(fixture.protocol.fixture.VERSION, "2.7.0")

    def test_three_constrained_nodes_and_both_listeners(self):
        self.run_mocked()

    def test_failures_prevent_success_report(self):
        for failure in ("probe", "cleanup", "inputs"):
            with self.subTest(failure=failure):
                self.run_mocked(failure)


if __name__ == "__main__":
    unittest.main()
