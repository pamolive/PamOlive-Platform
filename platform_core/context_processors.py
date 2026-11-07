from .services import module_catalog


def navigation_modules(request):
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return {"navigation_modules": []}
    return {
        "current_organization": getattr(request, "organization", None),
        "organizations": getattr(request, "organizations", []),
        "navigation_modules": [
            definition
            for definition, state in (
                module_catalog(request.organization)
                if getattr(request, "organization", None)
                else []
            )
            if state and state.enabled and definition.url_name
        ],
    }
