# Generated by Django 4.2.13 on 2024-07-04 18:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_alter_myuser_role_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='myuser',
            name='role_id',
            field=models.PositiveSmallIntegerField(blank=True, choices=[(1, 'Read Only'), (2, 'Read and Edit'), (3, 'Admin')], default=1, null=True),
        ),
    ]