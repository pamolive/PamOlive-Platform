"""One route set shared by the product URLconf and isolated interface tests."""

from django.urls import path

from .directory_reconciliation_views import account_review

urlpatterns = [
    path(
        "connectors/directories/<uuid:source_id>/review/",
        account_review,
        name="directory-account-review",
    ),
    path(
        "api/v1/directories/<uuid:source_id>/review/",
        account_review,
        {"api": True},
        name="api-directory-account-review",
    ),
    path(
        "connectors/directories/<uuid:source_id>/review/export/",
        account_review,
        {"export": True},
        name="directory-account-review-export",
    ),
]
