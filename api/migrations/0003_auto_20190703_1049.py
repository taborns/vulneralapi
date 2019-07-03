# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-07-03 10:49
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_file_project'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScanResult',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scan_version', models.IntegerField(default=0)),
                ('scanned_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ('scanned_at', 'scan_version'),
            },
        ),
        migrations.AddField(
            model_name='application',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='scanresult',
            name='project',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scans', to='api.Application'),
        ),
        migrations.AddField(
            model_name='file',
            name='scanResults',
            field=models.ManyToManyField(related_name='files', to='api.ScanResult'),
        ),
    ]
