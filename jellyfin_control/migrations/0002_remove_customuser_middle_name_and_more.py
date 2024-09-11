# Generated by Django 5.0.7 on 2024-08-24 11:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jellyfin_control', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='middle_name',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='username',
        ),
        migrations.AlterField(
            model_name='customuser',
            name='email',
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]
