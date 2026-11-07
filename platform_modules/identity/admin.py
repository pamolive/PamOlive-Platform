from django.contrib import admin

from .models import AccessAssignment, IdentityApplication


class AccessAssignmentInline(admin.TabularInline):
    model = AccessAssignment
    extra = 0


@admin.register(IdentityApplication)
class IdentityApplicationAdmin(admin.ModelAdmin):
    list_display = ("name", "key", "owner", "active", "assignment_count")
    list_filter = ("active",)
    search_fields = ("name", "key")
    inlines = (AccessAssignmentInline,)

    @admin.display(description="Accès")
    def assignment_count(self, obj):
        return obj.access_assignments.count()


@admin.register(AccessAssignment)
class AccessAssignmentAdmin(admin.ModelAdmin):
    list_display = ("user", "application", "entitlement", "role", "status", "expires_at")
    list_filter = ("status", "application")
    search_fields = ("user__username", "user__email", "entitlement")
    autocomplete_fields = ("user", "application", "role")
