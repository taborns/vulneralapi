from rest_framework import serializers
from api import models

class RecursiveField(serializers.Serializer):
    def to_representation(self, value):
        serializer = self.parent.parent.__class__(value, context=self.context)
        return serializer.data

class ApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Application
        fields = '__all__'

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
    class Meta:
        model = models.Issue
        fields = '__all__'


class ScanResultSerializer(serializers.ModelSerializer):
    project = ApplicationSerializer(read_only=True)
    class Meta:
        model = models.ScanResult
        fields = '__all__'
