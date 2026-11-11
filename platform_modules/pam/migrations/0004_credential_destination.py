from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("pam", "0003_recording_boundaries")]
    operations = [
        migrations.AddField(
            model_name="sessionendpoint",
            name="credential_seal",
            field=models.CharField(blank=True, editable=False, max_length=64),
        ),
        migrations.AddField(
            model_name="sessionendpoint",
            name="destination_epoch",
            field=models.PositiveIntegerField(default=1, editable=False),
        ),
    ]
