"""Separate historical, manual, collector and verified internal event authority."""

import uuid

import django.db.models.deletion
import django.db.models.manager
from django.conf import settings
from django.db import migrations, models
from django.db.models import Q
from django.utils import timezone


class Migration(migrations.Migration):
    dependencies = [
        ("access", "0014_accessintent_pam_trust"),
        ("connectors", "0011_scim_destination_binding"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="accessevent", name="provenance_channel",
            field=models.CharField(
                choices=[
                    ("legacy_unknown", "Provenance historique indéterminée"),
                    ("manual", "Saisie manuelle"),
                    ("collector", "Collecteur authentifié"),
                    ("internal", "Producteur interne vérifié"),
                ],
                default="legacy_unknown", editable=False, max_length=20,
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="accessevent", name="collector_source",
            field=models.ForeignKey(
                to="connectors.eventsource", null=True, blank=True, editable=False,
                on_delete=django.db.models.deletion.PROTECT, related_name="access_events",
            ),
        ),
        migrations.AddField(
            model_name="accessevent", name="manual_actor",
            field=models.ForeignKey(
                to=settings.AUTH_USER_MODEL, null=True, blank=True, editable=False,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="manual_access_events",
            ),
        ),
        migrations.AddField(
            model_name="accessevent", name="internal_principal",
            field=models.CharField(max_length=80, blank=True, editable=False, default=""),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="accessevent", name="facts_schema",
            field=models.CharField(max_length=40, blank=True, editable=False, default=""),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="accessevent", name="facts_digest",
            field=models.CharField(max_length=64, blank=True, editable=False, default=""),
            preserve_default=False,
        ),
        migrations.RemoveConstraint(
            model_name="accessevent", name="unique_access_source_event",
        ),
        migrations.AddConstraint(
            model_name="accessevent",
            constraint=models.CheckConstraint(
                condition=(
                    Q(provenance_channel="legacy_unknown", collector_source__isnull=True,
                      manual_actor__isnull=True, internal_principal="", facts_schema="",
                      facts_digest="")
                    | Q(provenance_channel="manual", collector_source__isnull=True,
                        manual_actor__isnull=False, internal_principal="",
                        facts_schema="event-facts/8", facts_digest__gt="")
                    | Q(provenance_channel="collector", collector_source__isnull=False,
                        manual_actor__isnull=True, internal_principal="",
                        facts_schema="event-facts/8", facts_digest__gt="")
                    | Q(provenance_channel="internal", collector_source__isnull=True,
                        manual_actor__isnull=True, internal_principal__gt="",
                        facts_schema="event-facts/8", facts_digest__gt="")
                ),
                name="access_event_provenance_shape",
            ),
        ),
        migrations.AddConstraint(
            model_name="accessevent",
            constraint=models.UniqueConstraint(
                fields=["organization", "source", "external_id"],
                condition=Q(provenance_channel="legacy_unknown"),
                name="unique_legacy_access_source_event",
            ),
        ),
        migrations.AddConstraint(
            model_name="accessevent",
            constraint=models.UniqueConstraint(
                fields=["organization", "manual_actor", "source", "external_id"],
                condition=Q(provenance_channel="manual"),
                name="unique_manual_access_event",
            ),
        ),
        migrations.AddConstraint(
            model_name="accessevent",
            constraint=models.UniqueConstraint(
                fields=["organization", "collector_source", "external_id"],
                condition=Q(provenance_channel="collector"),
                name="unique_collector_access_event",
            ),
        ),
        migrations.AddConstraint(
            model_name="accessevent",
            constraint=models.UniqueConstraint(
                fields=["organization", "internal_principal", "external_id"],
                condition=Q(provenance_channel="internal"),
                name="unique_internal_access_event",
            ),
        ),
        migrations.AddIndex(
            model_name="accessevent",
            index=models.Index(
                fields=["organization", "provenance_channel", "received_at"],
                name="access_acce_organiz_eb380e_idx",
            ),
        ),
        migrations.CreateModel(
            name="AccessProvenanceReceipt",
            fields=[
                ("id", models.UUIDField(
                    primary_key=True, default=uuid.uuid4, editable=False, serialize=False,
                )),
                ("version", models.CharField(
                    max_length=32, default="event-provenance/8", editable=False,
                )),
                ("channel", models.CharField(max_length=20, editable=False)),
                ("principal_id", models.CharField(max_length=180, editable=False)),
                ("credential_fingerprint", models.CharField(
                    max_length=64, blank=True, editable=False,
                )),
                ("facts_schema", models.CharField(max_length=40, editable=False)),
                ("facts_digest", models.CharField(max_length=64, editable=False)),
                ("first_received_at", models.DateTimeField(editable=False)),
                ("key_id", models.CharField(max_length=64, editable=False)),
                ("signature", models.CharField(max_length=64, editable=False)),
                ("organization", models.ForeignKey(
                    to="platform_core.organization", on_delete=django.db.models.deletion.PROTECT,
                )),
                ("event", models.OneToOneField(
                    to="access.accessevent", on_delete=django.db.models.deletion.PROTECT,
                    related_name="provenance_receipt",
                )),
                ("audit", models.OneToOneField(
                    to="platform_core.auditevent", on_delete=django.db.models.deletion.PROTECT,
                    related_name="access_provenance_receipt",
                )),
            ],
            options={"base_manager_name": "unscoped"},
            managers=[
                ("objects", django.db.models.manager.Manager()),
                ("unscoped", django.db.models.manager.Manager()),
            ],
        ),
        migrations.CreateModel(
            name="AccessEventConflict",
            fields=[
                ("id", models.UUIDField(
                    primary_key=True, default=uuid.uuid4, editable=False, serialize=False,
                )),
                ("attempted_digest", models.CharField(max_length=64, blank=True)),
                ("count", models.PositiveIntegerField(default=1)),
                ("first_seen_at", models.DateTimeField(default=timezone.now)),
                ("last_seen_at", models.DateTimeField(default=timezone.now)),
                ("organization", models.ForeignKey(
                    to="platform_core.organization", on_delete=django.db.models.deletion.PROTECT,
                )),
                ("event", models.ForeignKey(
                    to="access.accessevent", on_delete=django.db.models.deletion.PROTECT,
                    related_name="conflicts",
                )),
                ("audit", models.OneToOneField(
                    to="platform_core.auditevent", null=True, blank=True,
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="access_event_conflict",
                )),
            ],
            options={"base_manager_name": "unscoped"},
            managers=[
                ("objects", django.db.models.manager.Manager()),
                ("unscoped", django.db.models.manager.Manager()),
            ],
        ),
        migrations.AddConstraint(
            model_name="accesseventconflict",
            constraint=models.UniqueConstraint(
                fields=["organization", "event", "attempted_digest"],
                name="unique_access_event_conflict",
            ),
        ),
        migrations.CreateModel(
            name="AccessEventQuota",
            fields=[
                ("id", models.UUIDField(
                    primary_key=True, default=uuid.uuid4, editable=False, serialize=False,
                )),
                ("channel", models.CharField(max_length=20)),
                ("principal_key", models.CharField(max_length=180)),
                ("day", models.DateField()),
                ("accepted_count", models.PositiveIntegerField(default=0)),
                ("attempt_count", models.PositiveIntegerField(default=0)),
                ("denied_count", models.PositiveIntegerField(default=0)),
                ("organization", models.ForeignKey(
                    to="platform_core.organization", on_delete=django.db.models.deletion.PROTECT,
                )),
                ("first_denial_audit", models.ForeignKey(
                    to="platform_core.auditevent", null=True, blank=True,
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="first_event_quota_denials",
                )),
            ],
            options={"base_manager_name": "unscoped"},
            managers=[
                ("objects", django.db.models.manager.Manager()),
                ("unscoped", django.db.models.manager.Manager()),
            ],
        ),
        migrations.AddConstraint(
            model_name="accesseventquota",
            constraint=models.UniqueConstraint(
                fields=["organization", "channel", "principal_key", "day"],
                name="unique_access_event_quota",
            ),
        ),
    ]
