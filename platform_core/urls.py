from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("users/", views.user_list, name="user-list"),
    path("users/new/", views.user_create, name="user-create"),
    path("users/<int:user_id>/", views.user_edit, name="user-edit"),
    path("roles/", views.role_list, name="role-list"),
    path("roles/new/", views.role_create, name="role-create"),
    path("roles/<int:role_id>/", views.role_edit, name="role-edit"),
    path("modules/", views.module_list, name="module-list"),
    path("modules/<slug:module_key>/install/", views.module_install, name="module-install"),
    path("modules/<slug:module_key>/disable/", views.module_disable, name="module-disable"),
    path("audit/", views.audit_log, name="audit-log"),
    path("system/", views.system_status, name="system-status"),
]
