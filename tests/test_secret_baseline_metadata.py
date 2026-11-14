"""Prevent recurrence of a temporary CLI filter committed during metadata refresh."""

import copy
from unittest import TestCase

from deploy.check_secret_baseline import validate


class SecretBaselineMetadataTests(TestCase):
    def sample(self):
        return {
            "filters_used": [{"path": "detect_secrets.filters.heuristic.is_likely_id_string"}],
            "results": {
                "tests/fixture.py": [
                    {"filename": "tests/fixture.py", "line_number": 169, "is_secret": False}
                ]
            },
        }

    def test_relative_metadata_is_accepted_without_changing_decisions(self):
        value = self.sample()
        before = copy.deepcopy(value)
        result = validate(value)
        self.assertTrue(result["portable"])
        self.assertFalse(result["secret_scan_performed"])
        self.assertEqual(value, before)

    def test_dynamic_baseline_filter_is_refused_even_with_a_relative_filename(self):
        for name in ("C:\\Users\\synthetic\\temporary.baseline", "/tmp/run/baseline", "baseline"):
            value = self.sample()
            value["filters_used"].append(
                {"path": "detect_secrets.filters.common.is_baseline_file", "filename": name}
            )
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(value)

    def test_other_filename_settings_cannot_embed_a_machine_path(self):
        for name in ("C:/Users/synthetic/file", "/home/runner/file", "../file", "a\\file"):
            value = self.sample()
            value["filters_used"].append({"path": "synthetic.filter", "filename": name})
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(value)

    def test_result_names_and_row_names_must_be_identical_relative_paths(self):
        for name in ("/tmp/file", "C:/file", "../file", "tests\\file", "tests//file"):
            value = self.sample()
            value["results"][name] = value["results"].pop("tests/fixture.py")
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(value)
        value = self.sample()
        value["results"]["tests/fixture.py"][0]["filename"] = "another/file.py"
        with self.assertRaises(ValueError):
            validate(value)

    def test_invalid_line_types_or_shapes_are_refused(self):
        for number in (True, 0, -1, "169", None):
            value = self.sample()
            value["results"]["tests/fixture.py"][0]["line_number"] = number
            with self.subTest(number=number), self.assertRaises(ValueError):
                validate(value)
        for value in (None, [], {}, {"filters_used": [], "results": []}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(value)
