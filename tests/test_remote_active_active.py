from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Event
from unittest import skipUnless
from unittest.mock import Mock, patch

from django.db import connection, connections
from django.test import SimpleTestCase, TransactionTestCase

from deploy import check_remote_active_active as control
from deploy import remote_ha_node as node


def snapshot(instance="a", locked=True):
    return {
        "schema": control.FORMAT,
        "core_version": "0.2.0a16",
        "pg_version": 170001,
        "instance": instance * 64,
        "session_key": "b" * 64,
        "encryption_key": "c" * 64,
        "policy": "d" * 64,
        "https_origin": False,
        "locked": locked,
    }


class RemoteHAGuards(SimpleTestCase):
    def test_ssh_is_pinned_and_exec_only_accepts_an_inspected_container_id(self):
        remote = control.Node("lab-pam-a", "pamolive-platform-web-1", "pamolive-platform")
        args = remote.arguments(*remote.worker_args("a" * 64))
        self.assertIn("BatchMode=yes", args)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("ClearAllForwardings=yes", args)
        self.assertIn(
            "docker --host unix:///var/run/docker.sock exec -i --user 1000:1000", args[-1]
        )
        self.assertNotIn("sudo", args[-1])
        for invalid in ("-oProxyCommand=bad", "host;cmd", "../host", "host\n"):
            with self.subTest(invalid=invalid), self.assertRaises(control.CheckError):
                control.Node(invalid, "pamolive-web", "pamolive-platform")
        with self.assertRaises(control.CheckError):
            remote.worker_args("other-container")
        with self.assertRaises(control.CheckError):
            control.Node("lab-a", "other-web", "other-app")

    def test_unrelated_or_unhealthy_container_is_rejected_before_exec(self):
        info = dict(
            container="a" * 64,
            image="sha256:" + "b" * 64,
            project="other-project",
            service="web",
            running=True,
            health="healthy",
        )
        remote = control.Node("lab-a", "pamolive-web", "pamolive-platform")
        with patch.object(
            remote,
            "run",
            side_effect=["a" * 32, "synthetic-engine", control.json.dumps(info)],
        ) as mock:
            with self.assertRaisesMessage(control.CheckError, "scoped PAM-olive"):
                remote.describe()
        self.assertEqual(
            [call.args[0] for call in mock.call_args_list], ["cat", "docker", "docker"]
        )
        self.assertNotIn("Env", control.INSPECT)

    def test_keys_policy_versions_and_instance_identifiers_must_match_as_required(self):
        baseline, peer = snapshot(), snapshot("e", False)
        control.validate_peer(baseline, peer)
        changes = {
            "core_version": "0.2.0a17",
            "pg_version": 160001,
            "session_key": "f" * 64,
            "encryption_key": "f" * 64,
            "policy": "f" * 64,
            "https_origin": True,
            "instance": "a" * 64,
        }
        for key, different in changes.items():
            with self.subTest(key=key), self.assertRaises(control.CheckError):
                control.validate_peer(baseline, {**peer, key: different})
        with self.assertRaises(control.CheckError):
            control.validate_peer(baseline, {**peer, "locked": "false"})

    def test_only_distinct_hosts_equal_images_and_stable_identity_can_be_qualified(self):
        first, second = Mock(alias="lab-a"), Mock(alias="lab-b")
        a = {
            "container": "a" * 64,
            "image": "sha256:" + "e" * 64,
            "machine": "synthetic-host-1",
            "engine": "synthetic-engine-1",
        }
        b = dict(a, container="b" * 64, machine="synthetic-host-2", engine="synthetic-engine-2")
        first.describe.return_value = a
        for wrong in (dict(b, machine=a["machine"]), dict(b, image="sha256:" + "f" * 64)):
            second.describe.return_value = wrong
            with (
                patch.object(control, "shared_lock") as lock,
                self.assertRaises(control.CheckError),
            ):
                control.qualify(first, second)
            lock.assert_not_called()
        second.describe.return_value = b
        with patch.object(control, "shared_lock", return_value=snapshot()):
            report = control.qualify(first, second)
        self.assertTrue(report["shared_writable_postgresql_lock_namespace"])
        self.assertFalse(report["containers_restarted"])
        self.assertNotIn("synthetic-host", str(report))
        self.assertNotIn("session_key", report)

    def test_challenge_domain_and_secrets_are_not_reused_across_proofs(self):
        nonce = b"n" * 32
        session = node.proof("synthetic-only", nonce, b"session")
        self.assertNotEqual(session, node.proof("synthetic-only", nonce, b"encryption"))
        self.assertNotEqual(session, node.proof("synthetic-only", b"m" * 32, b"session"))
        self.assertNotEqual(node.lock_key(nonce), node.lock_key(b"m" * 32))


@skipUnless(connection.vendor == "postgresql", "Real PostgreSQL lock namespace required.")
class RemoteHALockExchangeTests(TransactionTestCase):
    def test_shared_lock_is_transaction_scoped_read_only_and_released_on_success(self):
        messages, finish = Queue(), Event()

        def hold():
            def release():
                with connection.cursor() as cursor:
                    cursor.execute("SHOW transaction_read_only")
                    if cursor.fetchone() != ("on",):
                        raise AssertionError("Qualification transaction must be read-only")
                if not finish.wait(8):
                    raise TimeoutError
                return "release\n"

            try:
                node.exchange(connection, "hold", b"t" * 32, read=release, emit=messages.put)
            finally:
                connections.close_all()

        with patch.object(node, "readiness", return_value=snapshot()):
            with ThreadPoolExecutor(max_workers=1) as executor:
                job = executor.submit(hold)
                try:
                    self.assertTrue(messages.get(timeout=5)["locked"])
                    node.exchange(connection, "probe", b"t" * 32, read=None, emit=messages.put)
                    self.assertFalse(messages.get(timeout=5)["locked"])
                finally:
                    finish.set()
                job.result(timeout=8)
            self.assertEqual(messages.get(timeout=5), {"released": True})
            node.exchange(connection, "probe", b"t" * 32, read=None, emit=messages.put)
            self.assertTrue(messages.get(timeout=5)["locked"])

    def test_disconnected_controller_does_not_leave_a_lock(self):
        output = []
        nonce = b"x" * 32
        with patch.object(node, "readiness", return_value=snapshot()):
            with self.assertRaisesMessage(RuntimeError, "did not confirm release"):
                node.exchange(connection, "hold", nonce, read=lambda: "", emit=output.append)
            self.assertFalse(connection.in_atomic_block)
            node.exchange(connection, "probe", nonce, read=None, emit=output.append)
        self.assertTrue(output[-1]["locked"])
