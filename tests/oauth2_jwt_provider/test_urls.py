#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
from unittest import TestCase

# Imports from Django
from django.core.urlresolvers import resolve, reverse

# Imports from Third Party Modules
from oauth2_provider.views import AuthorizationView

# Local Imports
from oauth2_jwt_provider.views import RestrictedApplicationList
from tests.oauth2_jwt_provider.urls import OAUTH_NAMESPACE


class TestJWTOAuthUrls(TestCase):
    """JWT OAuth urls unit tests"""

    def setUp(self):
        """setUp"""
        self.url_pattern = OAUTH_NAMESPACE + ':{}'

    def test_oauth2_jwt_provider_urls(self):
        """Test oauth2_jwt_provider_urls"""
        url_name = self.url_pattern.format('authorize')
        url = reverse(url_name)
        expected = '/oauth/authorize/'
        self.assertEqual(url, expected)
        resolved = resolve(expected)
        self.assertEqual(resolved.func.__name__, AuthorizationView.__name__)

        url_name = self.url_pattern.format('list')
        url = reverse(url_name)
        expected = '/oauth/applications/'
        self.assertEqual(url, expected)
        resolved = resolve(expected)
        self.assertEqual(
            resolved.func.__name__, RestrictedApplicationList.__name__
        )
