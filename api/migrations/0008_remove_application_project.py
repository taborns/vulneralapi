# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-07-04 07:10
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_auto_20190703_1234'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='application',
            name='project',
        ),
    ]