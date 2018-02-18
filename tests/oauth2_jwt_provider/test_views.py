#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage.
All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>

Unit test for oauth2_jwt_provider view mixins
"""

from __future__ import absolute_import, unicode_literals

# Imports from Django
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import RequestFactory, TestCase
from django.views.generic import View

# Local Imports
from oauth2_jwt_provider import views
from tests.helpers import mock_as_view

# Constants

# Helper Functions & Classes
User = get_user_model()


# Tests
class ViewsMixinTests(TestCase):
    """Unit test for oauth2_jwt_provider view mixins"""

    def setUp(self):
        """setUp"""
        class MockGroupRequiredView(views.GroupRequiredMixin, View):
            group_required = 'test_group'

        self.mock_view = MockGroupRequiredView(template_name='test_views.html')
        self.request = RequestFactory().get('/fake-path')
        self.user = User.objects.create(username='testuser')
        self.group = Group.objects.create(name='test_group')

        self.user.is_superuser = True
        self.request.user = self.user

    def test_check_membership(self):
        """Test GroupRequiredMixin check_membership method"""
        views.ALLOW_SUPERUSERS = True
        mock_view = mock_as_view(self.mock_view, self.request)
        membership = mock_view.check_membership(('test_group',))
        self.assertTrue(membership)

        views.ALLOW_SUPERUSERS = False
        membership = mock_view.check_membership(('test_group',))
        self.assertFalse(membership)

        self.user.groups.add(self.group)
        self.user.save()
        membership = mock_view.check_membership(('test_group',))
        self.assertTrue(membership)
