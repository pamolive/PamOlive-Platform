import json
from importlib.resources import files

from platform_core.extensions import ModuleManifest

module = ModuleManifest.from_dict(
    json.loads(files(__package__).joinpath("manifest.json").read_text(encoding="utf-8"))
)
