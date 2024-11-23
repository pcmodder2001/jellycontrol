# Generated by Django 5.0.7 on 2024-11-23 17:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jellyfin_control', '0008_remove_config_invite_code2'),
    ]

    operations = [
        migrations.AlterField(
            model_name='logentry',
            name='action',
            field=models.CharField(choices=[('LOGIN', 'Login'), ('CREATED', 'Created'), ('DELETED', 'Deleted'), ('INFO', 'Info'), ('WARNING', 'Warning'), ('ERROR', 'Error'), ('SETUP', 'Setup'), ('DOWNLOAD', 'Download'), ('UPLOAD', 'Upload')], max_length=20),
        ),
    ]
