# Generated by Django 5.0.7 on 2024-10-01 12:13

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('folder_management', '0002_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='folder',
            name='access_list',
            field=models.ManyToManyField(blank=True, related_name='shared_with_me_folders', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='folder',
            name='owner',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='sharedfolder',
            name='shared_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='folder_shared_by', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='sharedfolder',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
