# Generated by Django 5.0.7 on 2025-01-08 21:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jellyfin_control', '0011_config_jellyseer_api_key_config_jellyseer_url_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='config',
            name='jellyseerr_api_key',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='config',
            name='jellyseerr_url',
            field=models.URLField(blank=True, max_length=255, null=True),
        ),
    ]
