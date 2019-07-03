# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from api.models import *
# Register your models here.

admin.site.register( Issue )
admin.site.register( File )
admin.site.register( Application )
admin.site.register( ScanResult )
admin.site.register( SecuringFunc )
admin.site.register( IssueType )