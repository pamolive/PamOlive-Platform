import json
from copy import deepcopy
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, Mock, call, patch

from websockets.exceptions import ConnectionClosed

from deploy.active_active_fixture import require_test_database
from deploy.active_active_rdp import send_keepalives
from deploy.check_active_active import (
    PROJECT,
    Browser,
    CSRFParser,
    Qualification,
    partition_scope,
    safe_relay_state,
    totp,
    validate_configuration,
    validate_rdp_network,
)
from deploy.prepare_active_active_environment import environment
from platform_modules.pam.protocol import Instruction
from tests.fixtures.paint import PaintProof
from tests.fixtures.rdp import RDPFixture


def configuration():
    common = {
        "image": "pamolive-platform:qualification",
        "restart": "no",
        "ports": [{"host_ip": "127.0.0.1", "target": 8000}],
        "environment": {
            "DATABASE_URL": "postgresql://test:unused@postgres/test_pamolive_ha",
            "SECRET_KEY": "a" * 50,
            "PAMOLIVE_ENCRYPTION_KEY": "b" * 50,
            "PAMOLIVE_HA_QUALIFICATION": "1",
        },
    }
    services = {name: deepcopy(common) for name in ("node-a", "node-b")}
    for name, service in services.items():
        service["environment"]["PAMOLIVE_INSTANCE_ID"] = "qualification-" + name[-1]
    return {"services": services}


def partition_topology():
    network, name = "a" * 64, "private-postgresql"
    a, b, db = "b" * 64, "c" * 64, "d" * 64
    ips = {a: "172.20.0.2", b: "172.20.0.3", db: "172.20.0.4"}
    info = {
        "Name": name,
        "Id": network,
        "Driver": "bridge",
        "Containers": {key: {"IPv4Address": ip + "/16"} for key, ip in ips.items()},
    }
    nodes = [
        {
            "Id": key,
            "State": {"StartedAt": "fixture-start"},
            "NetworkSettings": {
                "Networks": {
                    PROJECT + "_default": {},
                    name: {"NetworkID": network, "IPAddress": ips[key], "Aliases": ["node-" + tag]},
                }
            },
        }
        for key, tag in ((a, "a"), (b, "b"))
    ]
    return info, *nodes, {"client": ips[a], "server": ips[db]}


class RDPKeepaliveTests(IsolatedAsyncioTestCase):
    async def test_browser_protocol_keepalive_only_sends_nop_and_exits_when_closed(self):
        websocket = SimpleNamespace(
            send=AsyncMock(side_effect=[None, ConnectionClosed(None, None)])
        )
        with patch("deploy.active_active_rdp.asyncio.sleep", new_callable=AsyncMock) as delay:
            await send_keepalives(websocket)
        self.assertEqual(delay.await_args_list, [call(5), call(5)])
        self.assertEqual(websocket.send.await_args_list, [call("3.nop;"), call("3.nop;")])


class ActiveActiveGuardTests(TestCase):
    def test_partition_only_targets_a_database_route_proved_on_the_external_bridge(self):
        info, a, b, route = partition_topology()
        self.assertEqual(partition_scope(info, a, b, route), (info["Id"], a["Id"], ["node-a"]))
        for mutation in (
            {"client": "172.17.0.1"},
            {"server": "172.17.0.1"},
            {"server": route["client"]},
            {"server": None},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                partition_scope(info, a, b, {**route, **mutation})
        for mutation in (
            {"Name": PROJECT + "_default"},
            {"Driver": "host"},
            {"Containers": {a["Id"]: info["Containers"][a["Id"]]}},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                partition_scope({**info, **mutation}, a, b, route)

    def test_partition_reconnects_only_owned_node_even_when_probe_fails(self):
        info, a, b, route = partition_topology()
        detached = deepcopy(a)
        del detached["NetworkSettings"]["Networks"][info["Name"]]
        check = Qualification("docker", "/not-used", database_partition=True)
        with (
            patch.object(check, "command", side_effect=[json.dumps([info]), "", ""]) as command,
            patch.object(
                check, "node", side_effect=[(a["Id"], a), (b["Id"], b), (a["Id"], detached)]
            ),
            patch.object(check, "fixture", side_effect=[route, {}, {"health": 200, "ingest": 201}]),
            self.assertRaisesRegex(RuntimeError, "must fail its health check"),
        ):
            check.check_database_partition(
                info["Name"], 1234, Mock(), {"run": "run", "source_token": "fixture-only"}, {}
            )
        self.assertEqual(
            command.call_args_list,
            [
                call("docker", "network", "inspect", info["Name"]),
                call("docker", "network", "disconnect", info["Id"], a["Id"]),
                call("docker", "network", "connect", "--alias", "node-a", info["Id"], a["Id"]),
            ],
        )

    def test_partition_survivor_commits_then_recovered_node_deduplicates_the_exact_event(self):
        info, a, b, route = partition_topology()
        detached = deepcopy(a)
        del detached["NetworkSettings"]["Networks"][info["Name"]]
        nodes = [(a["Id"], a), (b["Id"], b), (a["Id"], detached), (a["Id"], a)]
        initial = {"events": 2, "received_audits": 2, "other_events": 0, "audit_valid": True}
        final = {**initial, "events": 3, "received_audits": 3}
        event_body = json.dumps({"event_id": "fixture-event"})
        browser = Mock()
        browser.request.return_value = (200, None, "")
        check = Qualification("docker", "/not-used", database_partition=True)
        with (
            patch.object(check, "command", side_effect=[json.dumps([info]), "", ""]),
            patch.object(check, "node", side_effect=nodes),
            patch.object(
                check,
                "fixture",
                side_effect=[route, initial, {"health": 503, "ingest": 500}, initial, final],
            ),
            patch.object(check, "wait_ready", return_value=4321),
            patch("deploy.check_active_active.Browser") as peer,
        ):
            peer.return_value.request.side_effect = [
                (200, None, ""),
                (201, None, event_body),
                (200, None, event_body),
            ]
            report = check.check_database_partition(
                info["Name"], 1234, browser, {"run": "run", "source_token": "fixture-only"}, {}
            )
        self.assertTrue(all(report.values()))
        write, replay = peer.return_value.request.call_args_list[1:]
        self.assertEqual(write.args, (1234, "/api/v1/events/"))
        self.assertEqual(replay.args, (4321, "/api/v1/events/"))
        self.assertEqual(write.kwargs, replay.kwargs)

    def test_rdp_state_diagnostics_report_only_known_values(self):
        self.assertEqual(
            safe_relay_state(["failed", "qualification-a", "relay_owner_lost", False, True]),
            dict(
                status="failed",
                owner="qualification-a",
                reason="relay_owner_lost",
                complete=False,
                recorded=True,
            ),
        )
        self.assertEqual(
            safe_relay_state(["secret", "session", "opaque", 1, "other"]),
            dict(status="unknown", owner="unknown", reason="other", complete=None, recorded=None),
        )
        self.assertEqual(safe_relay_state(None), {"state": "unavailable"})

    def test_rdp_peer_network_is_private_scope_with_exact_two_nodes(self):
        info = {
            "Name": PROJECT + "_default",
            "Driver": "bridge",
            "Labels": {"com.docker.compose.project": PROJECT},
            "Containers": {"node-a": {}, "node-b": {}},
        }
        validate_rdp_network(info, ["node-a", "node-b"])
        for key, value in (
            ("Name", "production"),
            ("Driver", "host"),
            ("Labels", {"com.docker.compose.project": "production"}),
            ("Containers", {"node-a": {}, "node-b": {}, "outside": {}}),
        ):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_rdp_network({**info, key: value}, ["node-a", "node-b"])

    def test_rdp_peer_requires_a_specific_private_ipv4_interface_for_two_nodes(self):
        self.assertIsNone(RDPFixture().ha_bind)
        for address in ("10.1.2.3", "172.16.2.3", "192.168.1.2"):
            self.assertEqual(RDPFixture(ha_bind=address).ha_bind, address)
        for address in ("0.0.0.0", "127.0.0.1", "172.32.2.1", "8.8.8.8", "::1", "host.local"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                RDPFixture(ha_bind=address)

    def test_rdp_after_fault_requires_a_new_display_color_not_an_old_frame(self):
        pixels = PaintProof()
        before = Instruction("cfill", ("0", "0", "187", "216", "88", "255"))
        after = Instruction("cfill", ("0", "0", "80", "107", "215", "255"))
        pixels.observe(before)
        self.assertTrue(pixels.matches)
        pixels.expect((80, 107, 215))
        pixels.observe(before)
        self.assertFalse(pixels.matches)
        pixels.observe(after)
        self.assertTrue(pixels.matches)

    def test_only_identical_private_two_node_test_configuration_is_accepted(self):
        validate_configuration(configuration())
        mutations = (
            lambda config: config["services"].pop("node-b"),
            lambda config: config["services"]["node-a"]["environment"].update(
                DATABASE_URL="postgresql://x@y/pamolive_platform"
            ),
            lambda config: config["services"]["node-a"]["environment"].update(
                DATABASE_URL="postgresql://x@y/test_pamolive_ha?dbname=pamolive_platform"
            ),
            lambda config: config["services"]["node-b"]["environment"].update(
                DATABASE_URL="postgresql://x@y/test_pamolive_ha_other"
            ),
            lambda config: config["services"]["node-a"]["environment"].update(
                PAMOLIVE_HA_QUALIFICATION="0"
            ),
            lambda config: config["services"]["node-a"]["environment"].update(
                PAMOLIVE_INSTANCE_ID="production-a"
            ),
            lambda config: config["services"]["node-a"]["environment"].update(SECRET_KEY="c" * 50),
            lambda config: config["services"]["node-a"].update(image="other-image"),
            lambda config: config["services"]["node-a"].update(restart="always"),
            lambda config: config["services"]["node-a"].update(volumes=["production:/app"]),
            lambda config: config["services"]["node-a"]["ports"][0].update(host_ip="0.0.0.0"),
        )
        for mutate in mutations:
            config = configuration()
            mutate(config)
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError):
                validate_configuration(config)

    def test_fixture_refuses_sqlite_and_every_nonqualification_database(self):
        with patch.dict("os.environ", {"PAMOLIVE_HA_QUALIFICATION": "1"}):
            with self.assertRaises(RuntimeError):
                require_test_database()
            with patch("django.db.connection.vendor", "postgresql"):
                for name in (
                    "pamolive_platform",
                    "test_pamolive_platform",
                    "test_pamolive_ha_injected_name",
                    "postgres",
                ):
                    with patch.dict("django.db.connection.settings_dict", {"NAME": name}):
                        with self.subTest(name=name), self.assertRaises(RuntimeError):
                            require_test_database()
                with patch.dict("django.db.connection.settings_dict", {"NAME": "test_pamolive_ha"}):
                    with patch("django.db.connection.cursor") as cursor:
                        cursor.return_value.__enter__.return_value.fetchone.return_value = (
                            "test_pamolive_ha",
                        )
                        require_test_database()
                        cursor.return_value.__enter__.return_value.fetchone.return_value = (
                            "pamolive_platform",
                        )
                        with self.assertRaises(RuntimeError):
                            require_test_database()
        with patch.dict("os.environ", {"PAMOLIVE_HA_QUALIFICATION": "0"}):
            with self.assertRaises(RuntimeError):
                require_test_database()

    def test_environment_derives_only_the_dedicated_database_and_does_not_expand_credentials(self):
        result = environment(
            "postgresql://user:pw$token@postgres:5432/live?sslmode=require",
            image="app:check",
            network="private",
        )
        self.assertIn(
            "'postgresql://user:pw$token@postgres:5432/test_pamolive_ha?sslmode=require'", result
        )
        self.assertNotIn("/live", result)
        self.assertIn(
            "@host.docker.internal:5432/test_pamolive_ha",
            environment(
                "postgresql://user:pw@postgres:5432/live",
                image="app:check",
                network="private",
                host="host.docker.internal",
            ),
        )
        for unsafe in (
            "postgresql://u:p@host/live\n",
            "postgresql://u:p'@host/live",
            "postgresql://u:p\\@host/live",
            "postgresql://u:p@host/live?dbname=pamolive_platform",
            "postgresql://u:p@host/live?service=production",
        ):
            with self.subTest(value="redacted"), self.assertRaises(ValueError):
                environment(unsafe, image="app:check", network="private")

    def test_qualification_does_not_clean_up_a_project_it_has_not_started(self):
        check = Qualification("docker", "/not-used")
        with patch.object(check, "compose") as compose:
            check.cleanup()
        compose.assert_not_called()

    def test_totp_matches_the_rfc_vector_without_host_third_party_dependencies(self):
        self.assertEqual(totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", timestamp=59), "287082")

    def test_form_parser_and_cookie_request_do_not_echo_cookie_attributes(self):
        parser = CSRFParser()
        parser.feed('<input value="test-token" name="csrfmiddlewaretoken" type="hidden">')
        self.assertEqual(parser.token, "test-token")
        browser = Browser()
        browser.cookies.load("session=test-value; HttpOnly; Path=/; SameSite=Lax")
        with patch("http.client.HTTPConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.getheaders.return_value = []
            response.read.return_value = b"ok"
            browser.request(1234, "/")
            self.assertEqual(
                connection.return_value.request.call_args.kwargs["headers"]["Cookie"],
                "session=test-value",
            )
