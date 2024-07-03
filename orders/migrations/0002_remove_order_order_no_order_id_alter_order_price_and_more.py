# Generated by Django 4.2.13 on 2024-07-03 14:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('orders', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='order',
            name='order_no',
        ),
        migrations.AddField(
            model_name='order',
            name='id',
            field=models.BigAutoField(auto_created=True, default=1, primary_key=True, serialize=False, verbose_name='ID'),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='order',
            name='price',
            field=models.DecimalField(decimal_places=2, max_digits=10, null=True),
        ),
        migrations.AlterField(
            model_name='order',
            name='product_name',
            field=models.CharField(max_length=255),
        ),
        migrations.DeleteModel(
            name='MyUser',
        ),
    ]