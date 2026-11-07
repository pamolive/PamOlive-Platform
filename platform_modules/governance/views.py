from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from platform_modules.access.ui import scoped

from . import services
from .forms import (
    ContractForm,
    ParticipantForm,
    PolicyForm,
    SeparationForm,
    SupplierForm,
    scope_form,
)
from .models import (
    ApprovalPolicyRevision,
    ContractParticipant,
    SeparationRule,
    Supplier,
    SupplierContract,
)


@scoped("governance")
def index(request):
    return render(
        request,
        "governance/policies.html",
        {
            "suppliers": Supplier.objects.all(),
            "contracts": SupplierContract.objects.all(),
            "participants": ContractParticipant.objects.select_related(
                "contract", "identity"
            ).order_by("-valid_from")[:100],
            "rules": SeparationRule.objects.select_related("left_resource", "right_resource"),
            "policy": ApprovalPolicyRevision.objects.order_by("-sequence").first(),
        },
    )


@scoped("governance", roles=("admin",))
def edit(request, kind, object_id=None):
    if kind not in ("contract", "supplier", "participant", "policy", "separation"):
        raise Http404
    contract = get_object_or_404(SupplierContract.objects, pk=object_id) if object_id else None
    if kind == "contract":
        form = ContractForm(request.POST or None, contract=contract)
        title = "Publier une révision du contrat" if contract else "Nouveau contrat fournisseur"
    else:
        cls, title = {
            "supplier": (SupplierForm, "Nouveau fournisseur"),
            "participant": (ParticipantForm, "Inscrire un intervenant"),
            "policy": (PolicyForm, "Publier la politique d’approbation"),
            "separation": (SeparationForm, "Publier une incompatibilité de droits"),
        }[kind]
        form = scope_form(cls(request.POST or None))
    if request.method == "POST" and form.is_valid():
        try:
            if kind == "contract":
                services.publish_contract(
                    form.cleaned_data,
                    form.scopes(),
                    actor=request.user,
                    organization=request.organization,
                    contract_id=contract.pk if contract else None,
                )
            else:
                service = {
                    "supplier": services.create_supplier,
                    "participant": services.add_participant,
                    "policy": services.publish_policy,
                    "separation": services.publish_separation,
                }[kind]
                service(form.cleaned_data, actor=request.user, organization=request.organization)
            messages.success(
                request,
                "Publication enregistrée et auditée. Les révisions précédentes restent conservées.",
            )
            return redirect("governance-home")
        except ValidationError as error:
            form.add_error(None, error)
    return render(
        request,
        "platform_core/form.html",
        {"title": title, "section": "Contrats et politiques", "form": form},
    )


@scoped("governance")
def detail(request, object_id):
    contract = get_object_or_404(SupplierContract.objects, pk=object_id)
    return render(
        request,
        "governance/contract.html",
        {
            "contract": contract,
            "revisions": contract.revisions.select_related("sponsor")
            .prefetch_related("scopes__resource")
            .order_by("-sequence"),
        },
    )


@scoped("governance", roles=("admin",))
@require_POST
def withdraw(request, kind, object_id):
    if kind not in ("contract", "participant", "separation"):
        raise Http404
    model = {
        "contract": SupplierContract,
        "participant": ContractParticipant,
        "separation": SeparationRule,
    }[kind]
    get_object_or_404(model.objects, pk=object_id)
    try:
        services.withdraw(kind, object_id, actor=request.user, organization=request.organization)
        messages.success(
            request,
            "Retrait enregistré. Les retraits externes restent à confirmer par les connecteurs.",
        )
    except ValidationError as error:
        messages.error(request, "; ".join(error.messages))
    return redirect("governance-home")
