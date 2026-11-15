"""Installed child IO/import policy, composed from pinned mutation primitives."""

import builtins
import importlib.abc
import os
import socket
import sqlite3
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from support import load

REFERENCE = load("installed_tests.py")
DRIVERS = frozenset({"psycopg", "psycopg2", "asyncpg", "pg8000"})
APPLICATIONS = frozenset(
    {
        "django",
        "config",
        "platform_core",
        "platform_modules",
        "pamolive_vault_envelope",
        "boto3",
        "botocore",
        "requests",
        "ldap",
        "sqlalchemy",
    }
)
ForbiddenIO = REFERENCE.ForbiddenIO


class Policy:
    def __init__(self, *, prefix, stdlib, stage, controller, report, constants=os):
        self.guard = REFERENCE.Guards()
        self.roots = tuple(Path(path).resolve() for path in (prefix, stdlib, stage, controller))
        self.prefix = self.roots[0]
        self.base_site = self.roots[1] / "site-packages"
        self.report = Path(report).resolve()
        self.report_enabled = self.report_used = self.active = False
        self.constants = constants

    def imported(self, name):
        root = name.split(".", 1)[0].lower()
        if root in DRIVERS:
            self.guard.refuse("import.driver")
        if root in APPLICATIONS:
            self.guard.refuse("import.application_or_SDK")

    def audit(self, event, values):
        if not self.active:
            return
        if event in REFERENCE.FILESYSTEM_MUTATIONS:
            self.guard.refuse("file.mutation")
        if event.startswith(("socket.", "sqlite3.connect")) or event in {
            "subprocess.Popen",
            "os.system",
            "os.posix_spawn",
            "os.exec",
            "os.spawn",
        }:
            self.guard.refuse("external.audit")
        if event not in {"open", "os.listdir", "os.scandir"}:
            return
        if not values or type(values[0]) is int:
            self.guard.refuse("file.descriptor_open")
        try:
            resolved = Path(values[0]).resolve()
        except (OSError, ValueError, TypeError):
            self.guard.refuse("file.unresolved_path")
        try:
            writing = event == "open" and REFERENCE.open_mutates(
                values[1], values[2], self.constants
            )
        except (ValueError, TypeError, IndexError):
            self.guard.refuse("file.open_arguments")
        if writing:
            if not (
                resolved == self.report
                and self.report_enabled
                and not self.report_used
                and REFERENCE.exclusive_report_open(values[1], values[2], self.constants)
            ):
                self.guard.refuse("file.write")
            self.report_used = True
        elif resolved.is_relative_to(self.base_site) and not resolved.is_relative_to(self.prefix):
            self.guard.refuse("file.global_site")
        elif not any(resolved.is_relative_to(root) for root in self.roots):
            self.guard.refuse("file.read_outside_roots")

    def install(self):
        policy, original = self, builtins.__import__

        def guarded_import(name, *args, **kwargs):
            policy.imported(name)
            return original(name, *args, **kwargs)

        class Finder(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                policy.imported(fullname)
                return None

        class NoSocket(socket.socket):
            def __init__(self, *_args, **_kwargs):
                policy.guard.refuse("socket.constructor")

        stack = ExitStack()
        try:
            stack.enter_context(patch.object(builtins, "__import__", guarded_import))
            stack.enter_context(patch.object(socket, "socket", NoSocket))
            stack.enter_context(patch.object(socket, "getaddrinfo", self.guard.blocked("DNS")))
            stack.enter_context(
                patch.object(socket, "create_connection", self.guard.blocked("socket.connect"))
            )
            stack.enter_context(
                patch.object(sqlite3, "connect", self.guard.blocked("sqlite3.connect"))
            )
            stack.enter_context(
                patch.object(subprocess, "Popen", self.guard.blocked("subprocess.Popen"))
            )
            finder = Finder()
            sys.meta_path.insert(0, finder)
            stack.callback(sys.meta_path.remove, finder)
            sys.addaudithook(self.audit)
            self.active = True
            stack.callback(setattr, self, "active", False)
            return stack
        except BaseException:
            stack.close()
            raise

    def probe(self):
        self.guard.probing = True
        try:
            for callback in (
                lambda: socket.socket(),
                lambda: socket.getaddrinfo("fixture.invalid", 1),
                lambda: sqlite3.connect(":memory:"),
                lambda: subprocess.Popen(["never"]),
                lambda: __import__("psycopg"),
                lambda: open("/must-never-read-fixture", "rb"),
            ):
                try:
                    callback()
                except ForbiddenIO:
                    continue
                raise AssertionError("guard_probe_failed")
        finally:
            self.guard.probing = False
