"""Reject routing of the retired global prototype during delivery checks."""

from django.core.checks import Error, Tags, register
from django.urls import URLResolver, get_resolver


@register(Tags.urls)
def reject_retired_routes(app_configs=None, **kwargs):
    def visit(patterns):
        for pattern in patterns:
            if isinstance(pattern, URLResolver):
                yield from visit(pattern.url_patterns)
            elif getattr(pattern.callback, "pamolive_retired_route", False):
                yield Error(
                    "Une route du prototype global a été réintroduite.",
                    hint="Utiliser une vue organisationnelle actuelle, pas les vues historiques.",
                    obj=pattern,
                    id="pamolive.E010",
                )

    return list(visit(get_resolver().url_patterns))
