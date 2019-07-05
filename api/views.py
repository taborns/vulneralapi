# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from vulneral.analyze.PHPFile import PHPFile
from api import models, serializers
from rest_framework import generics,status
from django.http import HttpResponse, Http404
from rest_framework.response import Response
from vulneral.analyze.ProjectHandler import ProjectHandler
from rest_framework.views import APIView


# Create your views here.
class SingleFileView(APIView):


    def post(self, request, *args, **kwargs):
        serializer = serializers.SingleFileSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        file_name = serializer.validated_data.get('file_name')
        code = serializer.validated_data.get('code')
        phpFile = PHPFile(file_name, text_data=code)
        vulnTree = phpFile.handle()
        vulns = []
        
        for vuln in vulnTree.vulns:
            vulns.append( {'title' : vuln.title, 'line'  :  vuln.line} )
        
        vulns_serialized = serializers.SingleFileIssueSerializer( vulns, many=True)
        
        if phpFile.syntax_error:
            return Response({'error' : 'There is a syntax error in your code'},  status=status.HTTP_400_BAD_REQUEST)

        return Response(vulns_serialized.data, status=status.HTTP_200_OK)
        

            

class ApplicationView(generics.ListCreateAPIView):
    queryset = models.Application.objects.all()
    serializer_class = serializers.ApplicationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            application = models.Application.objects.get(name__iexact=serializer.validated_data.get('name'), version__iexact=serializer.validated_data.get('version'))
            serializer = self.get_serializer(instance=application,  data=serializer.validated_data, partial=True)
            serializer.is_valid(raise_exception=True)

            self.perform_update(serializer)
        except Exception as e:
            print e.message
            print "--" * 20
            application = self.perform_create(serializer)
        
        lastScanResult = application.scans.first()
        last_scan_version = 1    
        if lastScanResult:
            last_scan_version = lastScanResult.scan_version+1


        scanResult = models.ScanResult.objects.create(scan_version=last_scan_version, project=application)
        headers = self.get_success_headers(serializer.data)
        
        ProjectHandler.handle(request.data.get('project').temporary_file_path(), application, scanResult)

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

