# Generated by Django 5.0.7 on 2024-11-15 18:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jellyfin_control', '0005_invitation_user_alter_logentry_action'),
    ]

    operations = [
        migrations.AddField(
            model_name='config',
            name='invite_code',
            field=models.CharField(default='wdfwefwqef', max_length=50, unique=True),
            preserve_default=False,
        ),
    ]
