# Generated by Django 4.2.13 on 2024-07-04 19:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_alter_myuser_role_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='myuser',
            name='role_id',
        ),
        migrations.AddField(
            model_name='myuser',
            name='role',
            field=models.PositiveSmallIntegerField(choices=[('reader', 'Read Only'), ('editor', 'Read and Edit'), ('admin', 'Admin')], default=1, max_length=20),
            preserve_default=False,
        ),
    ]
