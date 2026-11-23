"""Offline custody contracts and bounded persistence using filesystem doubles."""

import stat
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pamolive_usage_anchor import anchor_store, codec, signed_anchor
from test_audit_archive import audit_rows, checkpoint, event, uid


class AnchorStoreTests(unittest.TestCase):
    def setUp(self):
        key = Ed25519PrivateKey.generate()
        self.public = key.public_key().public_bytes_raw()
        self.point = checkpoint(audit_rows([event("activation_challenge", uid(10))]))
        self.raw = signed_anchor.sign_checkpoint(self.point, public_key=self.public, sign=key.sign)
        self.pin = codec.sha(self.raw)
        self.store = anchor_store.AnchorStore("/custodian/records", owner_uid=1000)

    def test_only_absolute_clean_paths_and_dedicated_uid_are_accepted(self):
        for directory in (
            "/", "records", "/./records", "/../records", "/custodian//records", "/\0",
        ):
            with self.subTest(directory=directory), self.assertRaises(codec.Error):
                anchor_store.AnchorStore(directory, owner_uid=1000)
        for owner in (0, -1, 2**32 - 1, True, "1000"):
            with self.subTest(owner=owner), self.assertRaises(codec.Error):
                anchor_store.AnchorStore("/custodian", owner_uid=owner)

    def test_digest_is_checked_before_it_can_become_a_path(self):
        with patch.object(self.store, "_directory") as directory:
            for pin in ("../records", self.pin.upper(), b"a" * 64, "0" * 65):
                with self.subTest(pin=pin), self.assertRaises(codec.Error):
                    self.store.load(public_key=self.public, expected_sha256=pin)
            directory.assert_not_called()

    def test_save_verifies_signature_and_pin_before_any_filesystem_access(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        with patch.object(self.store, "_directory") as directory:
            for public, pin in ((other, self.pin), (self.public, "0" * 64)):
                with self.assertRaises(codec.Error) as failure:
                    self.store.save(self.raw, public_key=public, expected_sha256=pin)
                self.assertEqual(failure.exception.code, "anchor_refused")
            directory.assert_not_called()

    def test_save_and_load_use_exact_address_and_verify_original_bytes(self):
        with (
            patch.object(self.store, "_directory", return_value=nullcontext(9)),
            patch.object(self.store, "_staged_file", return_value=nullcontext("staged")) as stage,
            patch.object(anchor_store.os, "link") as link,
            patch.object(self.store, "_read", side_effect=[FileNotFoundError(), self.raw]) as read,
            patch.object(anchor_store.os, "fsync") as sync,
        ):
            self.store.save(self.raw, public_key=self.public, expected_sha256=self.pin)
            self.assertEqual(
                self.store.load(public_key=self.public, expected_sha256=self.pin),
                (self.point, self.raw),
            )
            stage.assert_called_once_with(9, self.raw)
            link.assert_called_once_with(
                "staged", self.pin + ".json", src_dir_fd=9, dst_dir_fd=9, follow_symlinks=False
            )
            self.assertEqual(
                read.call_args_list,
                [
                    call(9, self.pin + ".json", retained=self.raw,
                         maximum=signed_anchor.MAX_ANCHOR_BYTES),
                    call(9, self.pin + ".json"),
                ],
            )
            sync.assert_called_once_with(9)

    def test_existing_exact_receipt_is_synced_without_creating_a_new_file(self):
        with (
            patch.object(self.store, "_directory", return_value=nullcontext(9)),
            patch.object(self.store, "_staged_file") as stage,
            patch.object(self.store, "_read", return_value=self.raw) as read,
            patch.object(anchor_store.os, "fsync") as sync,
        ):
            self.store.save(self.raw, public_key=self.public, expected_sha256=self.pin)
            read.assert_called_once_with(
                9, self.pin + ".json", retained=self.raw, maximum=signed_anchor.MAX_ANCHOR_BYTES
            )
            stage.assert_not_called()
            sync.assert_called_once_with(9)

    def test_load_rejects_changed_bytes_and_wrong_key_even_at_exact_address(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        for raw, public in ((self.raw + b" ", self.public), (self.raw, other)):
            with (
                patch.object(self.store, "_directory", return_value=nullcontext(9)),
                patch.object(self.store, "_read", return_value=raw),
                self.assertRaises(codec.Error) as failure,
            ):
                self.store.load(public_key=public, expected_sha256=self.pin)
            self.assertEqual(failure.exception.status, 403)

    def test_read_checks_type_owner_mode_and_size_before_reading(self):
        filesystem = Mock(O_RDONLY=0, O_NOFOLLOW=1, O_NONBLOCK=2, O_CLOEXEC=4, O_NOCTTY=8)
        for mode, owner, size in (
            (stat.S_IFIFO | 0o600, 1000, 1),
            (stat.S_IFREG | 0o644, 1000, 1),
            (stat.S_IFREG | 0o600, 0, 1),
            (stat.S_IFREG | 0o600, 1000, signed_anchor.MAX_ANCHOR_BYTES + 1),
        ):
            filesystem.fstat.return_value = SimpleNamespace(
                st_mode=mode, st_uid=owner, st_size=size
            )
            with patch.object(anchor_store, "os", filesystem), self.assertRaises(codec.Error):
                self.store._read(9, self.pin + ".json")
        filesystem.read.assert_not_called()

    def test_other_platform_is_closed_before_posix_operations(self):
        with (
            patch.object(anchor_store, "sys", SimpleNamespace(platform="win32")),
            patch.object(anchor_store, "os") as filesystem,
            self.assertRaises(codec.Error) as failure,
        ):
            self.store.load(public_key=self.public, expected_sha256=self.pin)
        self.assertEqual(failure.exception.code, "unavailable")
        filesystem.geteuid.assert_not_called()
        filesystem.open.assert_not_called()
