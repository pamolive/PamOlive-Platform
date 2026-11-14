"""A runner's file limits never enlarge the disposable LDAP peer's allocation."""

import json
import subprocess
import sys
from unittest import skipUnless

from django.test import SimpleTestCase

from tests.fixtures.ldap_directory import bounded_command


@skipUnless(sys.platform == "linux", "Linux LDAP peer resource-limit gate")
class DirectoryPeerLimitTests(SimpleTestCase):
    def test_child_is_bounded_and_parent_limits_remain_unchanged(self):
        import resource

        before = resource.getrlimit(resource.RLIMIT_NOFILE)
        result = subprocess.run(
            bounded_command(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    "import resource,json;"
                    "print(json.dumps(resource.getrlimit(resource.RLIMIT_NOFILE)))",
                ]
            ),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        bound = min([256] + [value for value in before if value != resource.RLIM_INFINITY])
        self.assertEqual(json.loads(result.stdout), [bound, bound])
        self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE), before)
