"""Native review HTML, API and export use the guarded read-only projection."""

import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from django.conf import settings
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import resolve, reverse

from platform_core.models import ModuleActivation
from platform_core.services import install_module
from platform_core.tenancy import organization_context
from platform_modules.connectors.directory_inventory import map_directory_account
from platform_modules.connectors.models import ExternalChange
from platform_modules.identity.models import Grant

from .test_directory_inventory import DirectoryInventoryFixture


class Links(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.hrefs = []
        self.feed(html)

    def handle_starttag(self, tag, attributes):
        if tag == "a":
            self.hrefs.extend(value for key, value in attributes if key == "href")


@override_settings(
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
)
class DirectoryAccountReviewViewTests(DirectoryInventoryFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.accept()
        self.mutate(
            map_directory_account,
            self.source.pk,
            remote_id=self.remote_id,
            account_id=self.account.pk,
        )
        self.login(self.operator)

    def login(self, user):
        self.client.force_login(user)
        session = self.client.session
        session["organization_id"] = str(self.org.pk)
        session["mfa_verified_at"] = time.time()
        session.save()

    def url(self, kind="directory-account-review", source_id=None):
        return reverse(kind, args=[source_id or self.source.pk])

    def test_native_view_is_private_and_separates_current_owner_from_observation(self):
        before = (Grant.objects.count(), ExternalChange.objects.count())
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertContains(response, "Lecture uniquement")
        self.assertContains(response, "Propriétaire IAM actuel")
        self.assertContains(response, "ne sont pas réputées équivalentes")
        self.assertNotContains(response, self.credential["password"])
        self.assertEqual((Grant.objects.count(), ExternalChange.objects.count()), before)

    def test_api_and_export_keep_typed_authorities_and_no_secret(self):
        for name in ("api-directory-account-review", "directory-account-review-export"):
            response = self.client.get(self.url(name))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response["Cache-Control"], "no-store")
            data = response.json()
            self.assertEqual(data["schema"], "pamolive.directory-account-review/1")
            self.assertEqual(data["same_destination_relation"], "not_established")
            self.assertEqual(data["current_provider_state"], "not_asserted")
            self.assertFalse(data["can_apply"])
            self.assertNotIn(self.credential["password"], response.content.decode())
            self.assertNotIn("encrypted_credential", response.content.decode())
            if name.endswith("export"):
                self.assertEqual(
                    response["Content-Disposition"],
                    'attachment; filename="directory-account-review.json"',
                )

    def test_anonymous_and_foreign_organization_do_not_read_projection(self):
        for key in ("identity", "access", "connectors"):
            install_module(key, actor=self.admin, organization=self.other)
        with organization_context(self.other):
            original = self.org
            self.org = self.other
            try:
                source = self.create_source()
            finally:
                self.org = original
        for name in (
            "directory-account-review",
            "api-directory-account-review",
            "directory-account-review-export",
        ):
            self.assertEqual(self.client.get(self.url(name, source.pk)).status_code, 404)
        self.client.logout()
        self.assertEqual(self.client.get(self.url()).status_code, 302)

    def test_module_revocation_blocks_every_interface(self):
        for module in ("identity", "connectors"):
            ModuleActivation.objects.filter(organization=self.org, module_key=module).update(
                enabled=False
            )
            for name in (
                "directory-account-review",
                "api-directory-account-review",
                "directory-account-review-export",
            ):
                self.assertEqual(self.client.get(self.url(name)).status_code, 403)
            ModuleActivation.objects.filter(organization=self.org, module_key=module).update(
                enabled=True
            )

    def test_reviewer_can_read_but_post_does_not_start_an_action(self):
        self.login(self.reviewer)
        self.assertEqual(self.client.get(self.url()).status_code, 200)
        before = ExternalChange.objects.count()
        self.assertEqual(self.client.post(self.url(), {"apply": True}).status_code, 405)
        self.assertEqual(ExternalChange.objects.count(), before)

    def test_invalid_budgets_and_cursor_are_client_errors_without_authority(self):
        for query in (
            {"limit": "-1"},
            {"limit": "101"},
            {"history_limit": "0"},
            {"history_limit": "not-a-number"},
            {"cursor": "invalid"},
        ):
            response = self.client.get(self.url("api-directory-account-review"), query)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()["error"], "directory_request_invalid")
            self.assertNotIn(self.credential["password"], response.content.decode())

    def test_untrusted_names_remain_escaped_in_html(self):
        marker = '<script>alert("synthetic")</script>'
        self.accept(key="html-escape", records=[self.fact(self.remote_id, marker)])
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, marker)
        self.assertContains(response, "&lt;script&gt;")

    def test_routes_are_activated_in_the_canonical_product_urlconf(self):
        self.assertEqual(settings.ROOT_URLCONF, "config.urls")
        for name in (
            "directory-account-review",
            "api-directory-account-review",
            "directory-account-review-export",
        ):
            match = resolve(self.url(name))
            self.assertEqual(match.url_name, name)
            self.assertEqual(
                match.func.__module__, "platform_modules.connectors.directory_reconciliation_views"
            )

    def test_identity_to_source_to_account_review_navigation_is_read_only(self):
        before = (Grant.objects.count(), ExternalChange.objects.count())
        profile = self.client.get(reverse("identity360-detail", args=[self.identity.pk]))
        self.assertContains(profile, reverse("directory-index"))
        sources = self.client.get(reverse("directory-index"))
        detail_url = reverse("directory-detail", args=[self.source.pk])
        self.assertContains(sources, detail_url)
        detail = self.client.get(detail_url, {"limit": 1})
        review_link = next(
            link
            for link in Links(detail.content.decode()).hrefs
            if urlsplit(link).path == self.url()
        )
        self.assertEqual(parse_qs(urlsplit(review_link).query)["limit"], ["1"])
        review = self.client.get(review_link)
        self.assertEqual(review.status_code, 200)
        self.assertContains(review, detail_url)
        self.assertContains(review, "Les données sont relues au moment de l’export")
        self.assertEqual((Grant.objects.count(), ExternalChange.objects.count()), before)

    def test_identity_link_is_hidden_when_connect_is_disabled_without_directory_queries(self):
        ModuleActivation.objects.filter(organization=self.org, module_key="connectors").update(
            enabled=False
        )
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("identity360-detail", args=[self.identity.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Sources d’annuaire et revues des comptes")
        self.assertFalse(any('"connectors_directory' in row["sql"] for row in queries))
        self.assertEqual(self.client.get(self.url()).status_code, 403)

    def test_source_review_links_keep_signed_continuation_and_bounded_page(self):
        self.accept(
            key="navigation-page",
            records=[self.fact(username="first"), self.fact(username="second")],
        )
        detail_url = reverse("directory-detail", args=[self.source.pk])
        first = self.client.get(
            reverse("api-directory-inventory", args=[self.source.pk]), {"limit": 1}
        ).json()
        cursor = first["next_cursor"]
        self.assertTrue(cursor)
        detail = self.client.get(detail_url, {"limit": 1, "cursor": cursor})
        self.assertContains(detail, "jusqu’à 1 faits et 1 absences")
        self.assertContains(detail, "au plus 2 lignes sur une page")
        review_link = next(
            link
            for link in Links(detail.content.decode()).hrefs
            if urlsplit(link).path == self.url()
        )
        parameters = parse_qs(urlsplit(review_link).query)
        self.assertEqual(parameters, {"limit": ["1"], "cursor": [cursor]})
        response = self.client.get(
            self.url("api-directory-account-review"), {"limit": 1, "cursor": cursor}
        )
        self.assertEqual(response.status_code, 200)
        page = self.client.get(
            reverse("api-directory-inventory", args=[self.source.pk]),
            {"limit": 1, "cursor": cursor},
        ).json()
        contract = response.json()
        rows = contract["items"]
        self.assertEqual(contract["run"]["id"], page["run_id"])
        self.assertEqual(contract["source"], page["source"])
        self.assertEqual(contract["next_cursor"], page["next_cursor"])
        self.assertEqual(
            {row["observation"]["remote_id"]: row["observation"] for row in rows},
            {row["remote_id"]: row for row in page["items"] + page["not_observed"]},
        )
        self.assertEqual(
            response.json()["page_limits"],
            dict(facts=1, not_observed=1, total_items_max=2, history_per_section=20),
        )
        html = self.client.get(review_link)
        self.assertContains(html, "jusqu’à 1 faits et 1 absences")
        self.assertContains(html, "au plus 2 lignes de revue sur une page")
        self.assertContains(html, "Les absences ne prouvent aucune suppression")
        # The existing reader bounds facts and absent mappings separately.
        # Its last fact page may therefore also contain one absent mapping.
        self.assertEqual(
            {row["observation"]["remote_id"] for row in rows},
            {row["remote_id"] for row in page["items"] + page["not_observed"]},
        )
        for state in ("observed", "not_observed"):
            self.assertLessEqual(sum(row["observation_state"] == state for row in rows), 1)
