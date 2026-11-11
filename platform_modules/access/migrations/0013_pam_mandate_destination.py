from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("access", "0012_evaluation_proof_guard")]
    operations = [
        migrations.AddField(
            model_name="accessintent",
            name="pam_destination",
            field=models.JSONField(blank=True, default=dict, editable=False),
        ),
    ]
