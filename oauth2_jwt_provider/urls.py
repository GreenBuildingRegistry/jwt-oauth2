#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Django
import django

# Imports from Third Party Modules
import oauth2_provider.views as oauth2_views

# Local Imports
from oauth2_jwt_provider.views import (
    RestrictedApplicationDelete,
    RestrictedApplicationDetail,
    RestrictedApplicationList,
    RestrictedApplicationRegistration,
    RestrictedApplicationUpdate,
    RestrictedAuthorizedTokenDelete,
    RestrictedAuthorizedTokensList,
)

version = django.get_version()

if version.startswith('2'):
    from django.urls import include, re_path as url
else:
    from django.conf.urls import include, url

# OAuth2 provider endpoints
urlpatterns = [
    url(
        r'^authorize/$',
        oauth2_views.AuthorizationView.as_view(),
        name="authorize"
    ),
    url(
        r'^token/$',
        oauth2_views.TokenView.as_view(),
        name="token"
    ),
    url(
        r'^revoke-token/$',
        oauth2_views.RevokeTokenView.as_view(),
        name="revoke-token"
    ),
    url(
        r'^applications/$',
        RestrictedApplicationList.as_view(),
        name="list"
    ),
    url(
        r'^applications/register/$',
        RestrictedApplicationRegistration.as_view(),
        name="register"
    ),
    url(
        r'^applications/(?P<pk>\d+)/$',
        RestrictedApplicationDetail.as_view(),
        name="detail"
    ),
    url(
        r'^applications/(?P<pk>\d+)/delete/$',
        RestrictedApplicationDelete.as_view(),
        name="delete"
    ),
    url(
        r'^applications/(?P<pk>\d+)/update/$',
        RestrictedApplicationUpdate.as_view(),
        name="update"
    ),
    url(
        r'^authorized-tokens/$',
        RestrictedAuthorizedTokensList.as_view(),
        name="authorized-token-list"
    ),
    url(
        r'^authorized-tokens/(?P<pk>\d+)/delete/$',
        RestrictedAuthorizedTokenDelete.as_view(),
        name="authorized-token-delete"
    ),
]
