from rest_framework import serializers
from api import models


class SingleFileSerializer(serializers.Serializer):
    code = serializers.CharField(write_only=True, required=True)
    file_name = serializers.CharField(max_length=100, write_only=True, required=True)

class SingleFileIssueSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=200)
    line = serializers.IntegerField()


class RecursiveField(serializers.Serializer):
    def to_representation(self, value):
        serializer = self.parent.parent.__class__(value, context=self.context)
        return serializer.data

class ApplicationSerializer(serializers.ModelSerializer):
    project = serializers.FileField(write_only=True, required=True)
    class Meta:
        model = models.Application
        fields = '__all__'
    
    def create(self, validated_data):
        validated_data.pop('project')
        return super(ApplicationSerializer, self).create(validated_data)

class FileSerializer(serializers.ModelSerializer):
    project = ApplicationSerializer(read_only=True)

    class Meta:
        model = models.File
        exclude = ('scanResults',)

class SecuringFuncSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.SecuringFunc
        exclude = ('issueType',)


class IssueTypeSerializer(serializers.ModelSerializer):
    securing_funcs = SecuringFuncSerializer(many=True, read_only=True)
    class Meta:
        model = models.IssueType
        fields = '__all__'

class IssueSerializer(serializers.ModelSerializer):
    children = RecursiveField(read_only=True, many=True)
    issueType = IssueTypeSerializer(read_only=True)
    vulnFile = FileSerializer(read_only=True)
    class Meta:
        model = models.Issue
        fields = '__all__'


class ScanResultSerializer(serializers.ModelSerializer):
    project = ApplicationSerializer(read_only=True)
    class Meta:
        model = models.ScanResult
        fields = '__all__'
