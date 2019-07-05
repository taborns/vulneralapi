# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.
class Application(models.Model):
    version = models.CharField(max_length=10)
    name = models.CharField(max_length=200)
    #project = models.FileField(upload_to='projects/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "%s %s" % (self.name, self.version)

class IssueType(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    severity = models.IntegerField(choices=(
        (1, 'High'),
        (2, 'Medium'),
        (3, 'Low'),
    ))
    exampleCode = models.TextField()
    patch = models.TextField()
    patchCode = models.TextField()

    def __str__(self):
        return self.name

class SecuringFunc(models.Model):
    name = models.CharField(max_length=100)
    url = models.URLField()
    issueType = models.ForeignKey('IssueType', related_name='securing_funcs')

    def __str__(self):
        return "%s for %s"  % (self.name, self.issueType)
        
class ScanResult(models.Model):
    scan_version = models.IntegerField(default=0)
    project = models.ForeignKey('Application', related_name='scans')
    scanned_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if self.pk:
            self.scan_version = scan_version + 1
        super(ScanResult, self).save(*args, **kwargs)

    class Meta:
        ordering = ('scanned_at', 'scan_version')

    def __str__(self):
        return "%s - %s" % (self.project, self.scan_version)

class Issue(models.Model):
    title = models.CharField(max_length=200)
    line = models.CharField(max_length=5)
    snippet = models.TextField()
    parent = models.ForeignKey('self', blank=True, null=True, related_name='children')
    vulnFile = models.ForeignKey('File', related_name='issues')
    scanResult = models.ForeignKey('ScanResult', related_name='issues')
    issueType = models.ForeignKey('IssueType', null=True, blank=True, related_name='issues')
    
    def __str__(self):
        return self.title
        
class File(models.Model):
    path = models.CharField(max_length=200)
    name = models.CharField(max_length=100)
    project = models.ForeignKey('Application', related_name='files')
    scanResults = models.ManyToManyField('ScanResult', related_name='files')
    
    def __str__(self):
        return self.name
