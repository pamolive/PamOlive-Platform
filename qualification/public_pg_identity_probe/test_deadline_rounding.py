"""Reproduce floating clock boundaries without widening a deadline or doing IO."""

import math
import unittest
from unittest.mock import patch

import owner
import test_owner


class DeadlineRoundingTests(unittest.TestCase):
    def test_reproduced_reserve_overflow_is_rounded_toward_start(self):
        now = float.fromhex("0x1.9000000000003p+8")
        self.assertGreater((now + 120) - (now + 90), 30)
        work, cleanup = owner.run_deadlines(now)
        self.assertLessEqual(work, now + 90)
        self.assertLessEqual(cleanup, now + 120)
        self.assertTrue(0 < work - now <= 90)
        self.assertTrue(0 < cleanup - work <= 30)

    def test_exponent_boundaries_never_extend_original_windows(self):
        clocks = [0.0, 1.0, 400.0]
        for exponent in (8, 9, 10, 16, 26, 36):
            for offset in (1, 30, 90, 120):
                value = float(2**exponent - offset)
                clocks.extend((value, math.nextafter(value, math.inf), math.nextafter(value, 0)))
        for now in clocks:
            with self.subTest(clock=now.hex()):
                work, cleanup = owner.run_deadlines(now)
                self.assertTrue(0 < work - now <= 90)
                self.assertTrue(0 < cleanup - work <= 30)
                self.assertLessEqual(work, now + 90)
                self.assertLessEqual(cleanup, now + 120)

    def test_actual_owner_lifecycle_and_unknown_recoveries_at_counterexample_clock(self):
        case = test_owner.OwnerTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        with patch.object(
            owner.time, "monotonic", return_value=float.fromhex("0x1.9000000000003p+8")
        ):
            case.test_cli_owner_full_lifecycle_and_two_real_unknown_recoveries()
