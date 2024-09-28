# Generated by Django 5.0.7 on 2024-08-25 06:28

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('folder_management', '0004_alter_folder_binned'),
    ]

    operations = [
        migrations.AddField(
            model_name='sharedfolder',
            name='role',
            field=models.CharField(choices=[(1, 'Viewer'), (2, 'Commentor'), (3, 'Editor'), (4, 'Administrator')], default=1, max_length=255),
        ),
        migrations.AlterField(
            model_name='sharedfolder',
            name='folder',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='folder_management.folder'),
        ),
    ]
