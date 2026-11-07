from django.contrib import admin

from .models import AuditEvent, BusinessRole, InstalledModule, RolePermission


@admin.register(InstalledModule)
class InstalledModuleAdmin(admin.ModelAdmin):
    list_display = ("module_key", "version", "enabled", "installed_by", "updated_at")
    list_filter = ("enabled",)
    search_fields = ("module_key",)


class RolePermissionInline(admin.TabularInline):
    model = RolePermission
    extra = 1


@admin.register(BusinessRole)
class BusinessRoleAdmin(admin.ModelAdmin):
    list_display = ("name", "key", "member_count")
    search_fields = ("name", "key")
    filter_horizontal = ("members",)
    inlines = (RolePermissionInline,)

    @admin.display(description="Membres")
    def member_count(self, obj):
        return obj.members.count()


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "actor", "summary", "source_ip")
    list_filter = ("action",)
    search_fields = ("summary", "object_type", "object_id", "actor__username")
    readonly_fields = (
        "created_at",
        "actor",
        "action",
        "object_type",
        "object_id",
        "summary",
        "source_ip",
        "metadata",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
