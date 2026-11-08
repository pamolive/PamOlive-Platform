from types import ModuleType

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from django.urls import include, path

from platform_core import views
from platform_core.checks import reject_retired_routes
from platform_core.models import BusinessRole, RolePermission
from platform_core.permissions import has_permission
from platform_modules.identity import views as legacy_identity


class RetiredPrototypeTests(TestCase):
    def test_global_roles_never_grant_permissions_even_to_a_superuser(self):
        actor = get_user_model().objects.create_superuser("retired-admin")
        role = BusinessRole.objects.create(key="old-global", name="Historical role")
        role.members.add(actor)
        RolePermission.objects.create(role=role, code="core.users.manage")
        with self.assertNumQueries(0):
            self.assertFalse(has_permission(actor, "core.users.manage"))
        self.assertEqual(BusinessRole.objects.count(), 1)
        self.assertEqual(role.members.count(), 1)

    def test_retired_handlers_do_not_query_or_mutate_any_global_data(self):
        request = RequestFactory().post("/old/", {"is_superuser": "true"})
        handlers = (
            views.dashboard,
            views.user_list,
            views.user_create,
            views.user_edit,
            views.role_list,
            views.role_create,
            views.role_edit,
            views.audit_log,
            views.module_install,
            views.module_disable,
            views.system_status,
            legacy_identity.home,
            legacy_identity.application_create,
            legacy_identity.application_edit,
            legacy_identity.assignment_list,
            legacy_identity.assignment_create,
            legacy_identity.assignment_edit,
        )
        for handler in handlers:
            with self.subTest(handler=handler), self.assertNumQueries(0):
                response = handler(request, 123)
                self.assertEqual(response.status_code, 410)
                self.assertEqual(response["Cache-Control"], "no-store")
        with self.assertNumQueries(0):
            self.assertFalse(views.module_is_enabled("identity"))

    def test_current_routes_pass_and_nested_retired_routes_fail_delivery_check(self):
        self.assertEqual(reject_retired_routes(), [])
        urlconf = ModuleType("retired_route_fixture")
        urlconf.urlpatterns = [
            path(
                "legacy/",
                include(
                    [
                        path("users/", views.user_list),
                        path("identities/", legacy_identity.home),
                    ]
                ),
            )
        ]
        with override_settings(ROOT_URLCONF=urlconf):
            errors = reject_retired_routes()
        self.assertEqual([error.id for error in errors], ["pamolive.E010", "pamolive.E010"])
