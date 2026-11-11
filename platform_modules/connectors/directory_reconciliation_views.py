"""Native read-only account review, using the same contract for HTML/API/export."""

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from platform_core.view_access import scoped

from .directory_reconciliation import directory_account_review
from .directory_views import _failure, _private

REASONS = {
    "duplicate_login_requires_human_review": "Plusieurs objets déclarent le même nom de compte.",
    "group_observation_incomplete": "Les appartenances aux groupes sont incomplètes.",
    "explicit_mapping_inactive_or_missing": "La correspondance explicite manque ou est inactive.",
    "missing_observation_is_not_deletion": "Compte non observé : sa suppression n’est pas établie.",
    "source_enabled_state_unknown": "L’annuaire ne permet pas de déterminer l’état du compte.",
    "local_active_source_reports_disabled": "Compte local actif, déclaré désactivé par la source.",
    "local_inactive_source_reports_enabled": "Compte local inactif, déclaré actif par la source.",
    "scim_operation_not_confirmed": "Une opération SCIM n’est pas confirmée.",
    "late_scim_result_discarded": "Un résultat SCIM tardif a été écarté.",
    "invalid_scim_creation_proof": "Une preuve de création SCIM n’est pas vérifiable.",
    "scim_result_predates_inventory_acceptance": "Résultat SCIM antérieur à cet inventaire.",
    "directory_snapshot_incomplete": "L’observation d’annuaire est partielle.",
    "related_history_truncated": "La page ne contient pas toute l’histoire associée.",
}


@require_GET
@scoped("connectors")
def account_review(request, source_id, *, api=False, export=False):
    try:
        contract = directory_account_review(
            source_id,
            actor=request.user,
            organization=request.organization,
            limit=int(request.GET.get("limit", "100")),
            history_limit=int(request.GET.get("history_limit", "20")),
            cursor=request.GET.get("cursor") or None,
        )
        if api or export:
            response = JsonResponse(contract, json_dumps_params={"ensure_ascii": False})
            if export:
                response["Content-Disposition"] = (
                    'attachment; filename="directory-account-review.json"'
                )
            return _private(response)
        for row in contract["items"]:
            row["review_messages"] = [
                REASONS.get(reason, "Un point du dossier nécessite une revue.")
                for reason in row["review_reasons"]
            ]
        return _private(
            render(request, "connectors/directory_account_review.html", {"review": contract})
        )
    except (ObjectDoesNotExist, ValidationError, ValueError) as error:
        return _failure(error)
