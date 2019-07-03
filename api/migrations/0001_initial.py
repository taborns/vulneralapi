# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-07-02 22:17
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Application',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version', models.CharField(max_length=10)),
                ('name', models.CharField(max_length=200)),
                ('project', models.FileField(upload_to='projects/')),
            ],
        ),
        migrations.CreateModel(
            name='File',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('path', models.CharField(max_length=200)),
                ('name', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='Issue',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('line', models.CharField(max_length=5)),
                ('snippet', models.TextField()),
                ('parent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='children', to='api.Issue')),
                ('vulnFile', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='issues', to='api.File')),
            ],
        ),
    ]
