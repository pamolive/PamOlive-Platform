"""The test runner must not gain stock LDAP read/write through its traversal ACL."""

import stat
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from deploy import check_ldap_fixture_permissions as gate
from deploy.check_ldap_fixture_permissions import check_entry

ACL = "user::rw-\ngroup::r--\nother::---\n"


class LdapFixturePermissionTests(TestCase):
    def entry(self, mode, uid=999, gid=999, acl=ACL):
        return check_entry(SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid),
                           acl, 1000, {1000, 27})

    def test_stock_owner_and_group_retain_their_access(self):
        self.entry(stat.S_IFREG | 0o640)
        self.entry(stat.S_IFDIR | 0o700, acl="user::rwx\ngroup::---\nother::---\n")

    def test_world_read_or_write_would_be_exposed_by_traversal(self):
        for mode in (0o644, 0o602):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.entry(stat.S_IFREG | mode)

    def test_runner_group_or_ownership_is_not_ignored(self):
        for uid, gid in ((1000, 999), (999, 27)):
            with self.subTest(uid=uid, gid=gid), self.assertRaises(ValueError):
                self.entry(stat.S_IFREG | 0o640, uid=uid, gid=gid)

    def test_named_acl_cannot_escape_the_mode_check(self):
        for addition in ("user:1000:r--\n", "group:27:rw-\n", "mask::r--\n",
                         "default:user:1000:r--\n", "default:group:27:rw-\n"):
            with self.subTest(addition=addition), self.assertRaises(ValueError):
                self.entry(stat.S_IFREG | 0o600, acl=ACL + addition)

    def test_links_devices_and_executable_stock_data_are_refused(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFCHR | 0o600, stat.S_IFREG | 0o700):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.entry(mode)

    def test_inspection_does_not_hide_default_acls(self):
        parent = MagicMock()
        parent.lstat.return_value = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700, st_uid=999, st_gid=999
        )
        parent.iterdir.return_value = iter(())
        with (
            patch.object(gate.os, "name", "posix"),
            patch.object(gate.os, "geteuid", return_value=0, create=True),
            patch.object(gate, "Path", return_value=parent),
            patch.object(gate.subprocess, "run", return_value=SimpleNamespace(
                stdout="user::rwx\ngroup::---\nother::---\n", stderr=""
            )) as command,
        ):
            self.assertEqual(gate.inspect_stock(1000, {1000}), 1)
        self.assertEqual(command.call_args.args[0][1], "-cpn")
