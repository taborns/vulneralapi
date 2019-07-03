# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-07-03 11:03
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_auto_20190703_1049'),
    ]

    operations = [
        migrations.AddField(
            model_name='issue',
            name='scanResult',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='issues', to='api.ScanResult'),
            preserve_default=False,
        ),
    ]
