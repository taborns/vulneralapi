"""vulneralapi URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
from api import views as api_views
from rest_framework.authtoken import views as auth_view

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^api-token-auth/', auth_view.obtain_auth_token),
    url(r'^applications/$', api_views.ApplicationView.as_view(), name='user-list'),
    url(r'^issues/$', api_views.IssueView.as_view(), name='issue-list'),
    url(r'^files/$', api_views.FileView.as_view(), name='file-list'),
    url(r'^files/(?P<pk>\d+)/issues/$', api_views.FileIssuesView.as_view(), name='file-list'),
    url(r'^applications/(?P<pk>\d+)/files/$', api_views.ProjectFilesView.as_view(), name='file-list'),
    url(r'^applications/(?P<pk>\d+)/scans/$', api_views.ProjectScanResultView.as_view(), name='file-list'),
    url(r'^applications/(?P<app_pk>\d+)/scans/(?P<pk>\d+)/files/$', api_views.ScanResultFiles.as_view(), name='file-list'),
    url(r'^applications/(?P<app_pk>\d+)/scans/(?P<scanPk>\d+)/files/(?P<filePk>\d+)/$', api_views.ScanResultFileIssueView.as_view(), name='file-list'),

]
