import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("example_notes", "0001_initial"),
        ("platform_core", "0007_moduleevent_eventdelivery_eventattempt_and_more"),
    ]
    operations = [
        migrations.CreateModel(
            name="EventReceipt",
            fields=[
                ("event_id", models.UUIDField(primary_key=True, serialize=False)),
                ("topic", models.CharField(max_length=120)),
                ("aggregate_id", models.CharField(max_length=120)),
                ("occurred_at", models.DateTimeField()),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT, to="platform_core.organization"
                    ),
                ),
            ],
        ),
    ]
