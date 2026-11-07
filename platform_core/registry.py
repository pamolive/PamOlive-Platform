from dataclasses import dataclass, field


@dataclass(frozen=True)
class ModuleDefinition:
    key: str
    name: str
    version: str
    summary: str
    category: str
    is_paid: bool = False
    dependencies: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    url_name: str | None = None
    icon: str = "grid"
    metadata: dict = field(default_factory=dict)


_modules: dict[str, ModuleDefinition] = {}


def register_module(definition: ModuleDefinition):
    if definition.key in _modules:
        raise RuntimeError(f"Le module '{definition.key}' est déjà déclaré.")
    _modules[definition.key] = definition
    return definition


def get_module(key):
    return _modules.get(key)


def all_modules():
    return sorted(_modules.values(), key=lambda item: (item.category, item.name))
