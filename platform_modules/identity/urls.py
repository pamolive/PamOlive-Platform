from django.urls import path

from . import views

urlpatterns = [
    path("identities/", views.home, name="identity-home"),
    path("identities/applications/new/", views.application_create, name="application-create"),
    path(
        "identities/applications/<int:application_id>/",
        views.application_edit,
        name="application-edit",
    ),
    path("identities/assignments/", views.assignment_list, name="assignment-list"),
    path("identities/assignments/new/", views.assignment_create, name="assignment-create"),
    path(
        "identities/assignments/<int:assignment_id>/",
        views.assignment_edit,
        name="assignment-edit",
    ),
]
