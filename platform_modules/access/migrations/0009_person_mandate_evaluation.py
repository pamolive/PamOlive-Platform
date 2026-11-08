from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("access", "0008_person_bound_pam_mandates"),
        ("identity", "0007_binding_database_boundaries"),
    ]
    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[],
            state_operations=[
                migrations.AlterField(
                    model_name="accessevaluation",
                    name="rule_version",
                    field=models.CharField(default="access-context/5", max_length=30),
                )
            ],
        )
    ]
