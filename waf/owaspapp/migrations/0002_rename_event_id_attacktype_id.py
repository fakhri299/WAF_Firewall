# Generated by Django 5.0 on 2023-12-08 18:03

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('owaspapp', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='attacktype',
            old_name='event_id',
            new_name='id',
        ),
    ]