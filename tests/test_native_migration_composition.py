"""Real synthetic TARs exercise the composed physical-byte guards together."""

import hashlib
import tempfile
from pathlib import Path
from unittest import TestCase

from deploy import qualify_image_scan as gate
from tests.test_expat_product import elf, fixture, tar_bytes


class NativeMigrationCompositionTests(TestCase):
    def facts(self, raw, *, forbidden=(), reject_cjson=True, held=False):
        with tempfile.TemporaryDirectory(prefix="native-composition-data-") as folder:
            archive = Path(folder) / "synthetic.tar"
            archive.write_bytes(raw)
            if held:
                with archive.open("rb") as stream:
                    return gate.archive_facts(
                        archive,
                        [],
                        archive_stream=stream,
                        forbidden_elf_sha256=forbidden,
                        reject_cjson_elf=reject_cjson,
                    )
            return gate.archive_facts(
                archive,
                [],
                forbidden_elf_sha256=forbidden,
                reject_cjson_elf=reject_cjson,
            )

    def hidden(self, binary):
        # The final resolved filesystem lacks this file, but the vulnerable
        # physical bytes are still present in the first image layer.
        return fixture(
            extra_layers=[
                tar_bytes({"/usr/lib/hidden.so": binary}),
                tar_bytes({"/usr/lib/.wh.hidden.so": b""}),
            ]
        )[0]

    def test_clean_archive_passes_both_guards_with_path_and_held_FD(self):
        raw, _ = fixture()
        forbidden = [hashlib.sha256(elf(b"old-provider-not-present")).hexdigest()]
        for held in (False, True):
            with self.subTest(held=held):
                facts = self.facts(raw, forbidden=forbidden, held=held)
                self.assertEqual(facts.elf_set["elf_count"], 4)
                self.assertEqual(len(facts.layer_digests), 1)

    def test_whiteout_cannot_hide_forbidden_old_Expat_hash_when_JSON_guard_is_on(self):
        binary = elf(b"old-provider")
        raw = self.hidden(binary)
        for held in (False, True):
            with self.subTest(held=held), self.assertRaisesRegex(
                gate.ScanPolicyError, "forbidden_physical_elf"
            ):
                self.facts(raw, forbidden=[hashlib.sha256(binary).hexdigest()], held=held)

    def test_whiteout_cannot_hide_cJSON_symbols_when_old_hash_guard_is_on(self):
        raw = self.hidden(elf(b"cJSON_Compare"))
        forbidden = [hashlib.sha256(elf(b"old-provider-not-present")).hexdigest()]
        for held in (False, True):
            with self.subTest(held=held), self.assertRaisesRegex(
                gate.ScanPolicyError, "cjson_elf_symbol"
            ):
                self.facts(raw, forbidden=forbidden, held=held)

    def test_final_overwrite_cannot_hide_cJSON_from_combined_checks(self):
        target = "/usr/lib/x86_64-linux-gnu/libexpat.so.1.13.1"
        raw, _ = fixture(extra_layers=[tar_bytes({target: elf(b"cJSONUtils_ApplyPatches")})])
        forbidden = [hashlib.sha256(elf(b"old-provider-not-present")).hexdigest()]
        with self.assertRaisesRegex(gate.ScanPolicyError, "cjson_elf_symbol"):
            self.facts(raw, forbidden=forbidden, held=True)

    def test_each_guard_remains_effective_without_the_other_optional_guard(self):
        binary = elf(b"old-provider")
        with self.assertRaisesRegex(gate.ScanPolicyError, "forbidden_physical_elf"):
            self.facts(
                self.hidden(binary),
                forbidden=[hashlib.sha256(binary).hexdigest()],
                reject_cjson=False,
            )
        with self.assertRaisesRegex(gate.ScanPolicyError, "cjson_elf_symbol"):
            self.facts(self.hidden(elf(b"cJSON_Compare")), forbidden=())

    def test_combined_options_keep_both_closed_input_contracts(self):
        raw, _ = fixture()
        for forbidden, reject, code in (
            (["invalid"], True, "forbidden_elf_hashes"),
            ([], 1, "archive_cjson_option"),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(gate.ScanPolicyError, code):
                self.facts(raw, forbidden=forbidden, reject_cjson=reject)
