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


class ModuleDependencyError(ValueError):
    pass


def dependency_closure(key):
    """Return registered definitions once, including all indirect requirements."""
    visiting = set()
    visited = {}

    def visit(current):
        if current in visiting:
            raise ModuleDependencyError("Cycle de dépendances entre modules.")
        if current in visited:
            return
        definition = get_module(current)
        if definition is None:
            raise ModuleDependencyError("Dépendance de module non livrée.")
        visiting.add(current)
        for dependency in definition.dependencies:
            visit(dependency)
        visiting.remove(current)
        visited[current] = definition

    visit(key)
    return tuple(visited.values())


def register_module(definition: ModuleDefinition):
    if definition.key in _modules:
        raise RuntimeError(f"Le module '{definition.key}' est déjà déclaré.")
    _modules[definition.key] = definition
    return definition


def get_module(key):
    return _modules.get(key)


def all_modules():
    return sorted(_modules.values(), key=lambda item: (item.category, item.name))
