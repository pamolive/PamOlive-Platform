import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("platform_core", "0001_initial"),
    ]
    operations = [
        migrations.CreateModel(
            name="IdentityApplication",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("name", models.CharField(max_length=160, unique=True)),
                ("key", models.SlugField(max_length=80, unique=True)),
                ("description", models.TextField(blank=True)),
                ("active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "owner",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="owned_identity_applications",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "application connectée",
                "verbose_name_plural": "applications connectées",
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="AccessAssignment",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "entitlement",
                    models.CharField(
                        help_text="Droit ou profil cible dans l'application.", max_length=160
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("active", "Actif"),
                            ("pending", "En attente d'approbation"),
                            ("revoked", "Révoqué"),
                        ],
                        default="active",
                        max_length=15,
                    ),
                ),
                ("granted_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("justification", models.TextField(blank=True)),
                (
                    "application",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="access_assignments",
                        to="identity.identityapplication",
                    ),
                ),
                (
                    "role",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="application_assignments",
                        to="platform_core.businessrole",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="identity_access_assignments",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "attribution d'accès",
                "verbose_name_plural": "attributions d'accès",
            },
        ),
        migrations.AddConstraint(
            model_name="accessassignment",
            constraint=models.UniqueConstraint(
                fields=("user", "application", "entitlement"), name="unique_identity_assignment"
            ),
        ),
    ]
