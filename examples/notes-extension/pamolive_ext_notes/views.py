from django import forms
from django.core.exceptions import ValidationError
from django.shortcuts import redirect, render

from .services import create_note, list_notes


class NoteForm(forms.Form):
    title = forms.CharField(label="Titre", max_length=160)
    body = forms.CharField(label="Note", max_length=2000, widget=forms.Textarea)


def index(request):
    return render(
        request,
        "pamolive_ext_notes/index.html",
        {
            "notes": list_notes(actor=request.user, organization=request.organization),
            "form": NoteForm(),
        },
    )


def create(request):
    form = NoteForm(request.POST)
    if form.is_valid():
        try:
            create_note(actor=request.user, organization=request.organization, **form.cleaned_data)
            return redirect("ext-example_notes:home")
        except ValidationError as error:
            form.add_error(None, error)
    return render(
        request,
        "pamolive_ext_notes/index.html",
        {"notes": list_notes(actor=request.user, organization=request.organization), "form": form},
        status=400,
    )
