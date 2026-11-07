# Generated manually for PAM-olive Core.
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(
            name="BusinessRole",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("key", models.SlugField(max_length=80, unique=True)),
                ("name", models.CharField(max_length=120)),
                ("description", models.TextField(blank=True)),
                (
                    "members",
                    models.ManyToManyField(
                        blank=True,
                        related_name="pamolive_business_roles",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "rôle métier",
                "verbose_name_plural": "rôles métier",
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="AuditEvent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("action", models.CharField(db_index=True, max_length=120)),
                ("object_type", models.CharField(blank=True, max_length=120)),
                ("object_id", models.CharField(blank=True, max_length=120)),
                ("summary", models.CharField(max_length=255)),
                ("source_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="pamolive_audit_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "événement d'audit",
                "verbose_name_plural": "événements d'audit",
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="InstalledModule",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("module_key", models.SlugField(max_length=80, unique=True)),
                ("version", models.CharField(max_length=30)),
                ("enabled", models.BooleanField(default=True)),
                (
                    "installed_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="installed_pamolive_modules",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"verbose_name": "module installé", "verbose_name_plural": "modules installés"},
        ),
        migrations.CreateModel(
            name="RolePermission",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("code", models.CharField(max_length=120)),
                (
                    "role",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="permission_grants",
                        to="platform_core.businessrole",
                    ),
                ),
            ],
            options={
                "verbose_name": "permission métier",
                "verbose_name_plural": "permissions métier",
            },
        ),
        migrations.AddConstraint(
            model_name="rolepermission",
            constraint=models.UniqueConstraint(
                fields=("role", "code"), name="unique_role_permission"
            ),
        ),
    ]
