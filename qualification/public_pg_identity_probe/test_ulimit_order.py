"""Canonical CLI Ulimits order; synthetic profile data only, never an Engine."""

import copy
import unittest
from unittest import mock

import probe as p
from test_probe import PROFILE, RUN, row

CANONICAL = [
    {"Name": "core", "Hard": 0, "Soft": 0},
    {"Name": "nofile", "Hard": 64, "Soft": 64},
]


class UlimitOrderTests(unittest.TestCase):
    def test_canonical_positive_reproduces_old_refusal_then_passes_new_constant(self):
        candidate = row()
        candidate["HostConfig"]["Ulimits"] = copy.deepcopy(CANONICAL)
        old_host = p.HOST | {"Ulimits": list(reversed(CANONICAL))}
        with (
            mock.patch.object(p, "HOST", old_host),
            self.assertRaisesRegex(p.Refusal, "HOST_PROFILE"),
        ):
            p.inspect_profile(candidate, RUN, PROFILE)
        self.assertEqual(p.HOST["Ulimits"], CANONICAL)
        p.inspect_profile(candidate, RUN, PROFILE)
        self.assertFalse(p.same(CANONICAL, list(reversed(CANONICAL))))

    def test_names_values_duplicates_presence_types_and_old_order_still_refuse(self):
        variants = [
            None,
            {},
            [],
            CANONICAL[:1],
            CANONICAL + CANONICAL[:1],
            [CANONICAL[0], CANONICAL[0]],
            [CANONICAL[1], CANONICAL[1]],
            list(reversed(CANONICAL)),
            [CANONICAL[0] | {"Name": "foreign"}, CANONICAL[1]],
            [CANONICAL[0], CANONICAL[1] | {"Hard": 65}],
            [CANONICAL[0], CANONICAL[1] | {"Soft": 63}],
            [CANONICAL[0] | {"Soft": False}, CANONICAL[1]],
            [CANONICAL[0], CANONICAL[1] | {"Hard": "64"}],
            [CANONICAL[0] | {"extra": "foreign"}, CANONICAL[1]],
            [{"Name": "core", "Hard": 0}, CANONICAL[1]],
        ]
        for limits in variants:
            candidate = row()
            candidate["HostConfig"]["Ulimits"] = copy.deepcopy(limits)
            with self.subTest(limits=limits), self.assertRaisesRegex(p.Refusal, "HOST_PROFILE"):
                p.inspect_profile(candidate, RUN, PROFILE)
        candidate = row()
        del candidate["HostConfig"]["Ulimits"]
        with self.assertRaisesRegex(p.Refusal, "HOST_PROFILE"):
            p.inspect_profile(candidate, RUN, PROFILE)

    def test_create_options_and_all_other_start_properties_remain_closed(self):
        args = p.arguments()
        self.assertEqual(
            [args[index + 1] for index, item in enumerate(args) if item == "--ulimit"],
            ["nofile=64:64", "core=0:0"],
        )
        for location, key, value in (
            ("HostConfig", "NetworkMode", "host"),
            ("HostConfig", "ReadonlyRootfs", False),
            ("HostConfig", "Privileged", True),
            ("Config", "User", "999:999"),
        ):
            candidate = row()
            candidate[location][key] = value
            with self.subTest(key=key), self.assertRaises(p.Refusal):
                p.inspect_profile(candidate, RUN, PROFILE)
