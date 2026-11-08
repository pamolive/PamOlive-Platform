"""Versioned extension contract. Python packages are trusted deployment code, not a sandbox."""

from .manifest import Dependency, ModuleManifest, Permission, Route

__all__ = ["Dependency", "ModuleManifest", "Permission", "Route"]
