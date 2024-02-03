# Generated by Django 4.2.7 on 2024-02-01 19:05

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0021_eventstream"),
    ]

    operations = [
        migrations.AlterField(
            model_name="permission",
            name="resource_type",
            field=models.TextField(
                choices=[
                    ("activation", "activation"),
                    ("activation_instance", "activation_instance"),
                    ("audit_rule", "audit_rule"),
                    ("audit_event", "audit_event"),
                    ("task", "task"),
                    ("user", "user"),
                    ("project", "project"),
                    ("inventory", "inventory"),
                    ("extra_var", "extra_var"),
                    ("rulebook", "rulebook"),
                    ("role", "role"),
                    ("decision_environment", "decision_environment"),
                    ("credential", "credential"),
                    ("event_stream", "event_stream"),
                ]
            ),
        ),
    ]
