# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from api import models, serializers
from rest_framework import generics,status
from django.http import HttpResponse
from rest_framework.response import Response
from vulneral.analyze.ProjectHandler import ProjectHandler

# Create your views here.

class ApplicationView(generics.ListCreateAPIView):
    queryset = models.Application.objects.all()
    serializer_class = serializers.ApplicationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        application = self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        
        ProjectHandler.handle(application.project.url)

        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
    def perform_create(self, serializer):
        return serializer.save()

class IssueView(generics.ListCreateAPIView):
    queryset = models.Issue.objects.all()
    serializer_class = serializers.IssueSerializer

def list(self, request, *args, **kwargs):
    serializer = self.get_serializer(models.Issue.objects.filter(parent__isnull=True), many=True)
    return Response(serializer.data)

class FileView(generics.ListCreateAPIView):
    queryset = models.File.objects.all()
    serializer_class = serializers.FileSerializer

class FileIssuesView(generics.ListAPIView):
    queryset = models.Issue.objects.all()
    serializer_class = serializers.IssueSerializer

    def list(self, request, pk,  *args, **kwargs):
        phpFile = models.File.objects.get(pk=pk)
        serializer = self.get_serializer(phpFile.issues.all(), many=True)
        return Response(serializer.data)

class ProjectFilesView(generics.ListAPIView):
    queryset = models.File.objects.all()
    serializer_class = serializers.FileSerializer

    def list(self, request, pk,  *args, **kwargs):
        application = models.Application.objects.get(pk=pk)
        serializer = self.get_serializer(application.files.all(), many=True)
        return Response(serializer.data)

class ProjectScanResultView(generics.ListAPIView):
    queryset = models.ScanResult.objects.all()
    serializer_class = serializers.ScanResultSerializer

    def list(self, request, pk, *args, **kwargs):
        print "HERE AND THERE"
        application = models.Application.objects.get(pk=pk)
        serializer = self.get_serializer(application.scans.all(), many=True)
        return Response(serializer.data)

class ScanResultFiles(generics.ListAPIView):
    queryset = models.File.objects.all()
    serializer_class = serializers.FileSerializer

    def list(self, request, app_pk, pk, *args, **kwargs):
        application = models.Application.objects.get(pk=app_pk)
        scanResult = models.ScanResult.objects.get(pk=pk, project=application)
        serializer = self.get_serializer(scanResult.files.all(), many=True)
        return Response(serializer.data)


class ScanResultFileIssueView(generics.ListAPIView):
    queryset = models.Issue.objects.all()
    serializer_class = serializers.IssueSerializer
    
    def list(self, request, app_pk, scanPk,filePk, *args, **kwargs):
        application = models.Application.objects.get(pk=app_pk)

        scanResult = models.ScanResult.objects.get(pk=scanPk, project=application)
        vulnFile = models.File.objects.get(pk=filePk)

        serializer = self.get_serializer(scanResult.issues.filter(vulnFile=vulnFile,parent__isnull=True, scanResult=scanResult), many=True)
        return Response(serializer.data)