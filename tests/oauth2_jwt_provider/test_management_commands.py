#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2017 Earth Advantage. 
All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>

Unit tests for oauth2_jwt_provider django management commands
"""

# Imports from Standard Library
import mock
from django.core.management import call_command, CommandError
from django.test import TestCase
from django.utils.six import StringIO
from django.contrib.auth import get_user_model

# Imports from Third Party Modules
from oauth2_provider.models import get_application_model

# Local Imports
from oauth2_jwt_provider.management.commands._private import (
    AddGroupCommand,
    SkipAuthCommand
)
from tests.helpers import UserFactory, ApplicationFactory, GroupFactory
from oauth2_jwt_provider.settings import jwt_oauth2_settings
# Constants
User = get_user_model()
TRUSTED_GROUP = 'trusted_developers'
# Helper Functions & Classes
Application = get_application_model()


# Tests

class ManagementCommandsTests(TestCase):

    def setUp(self):
        """setUp"""
        self.user = UserFactory(username='TestUser')
        jwt_oauth2_settings.TRUSTED_OAUTH_GROUP = TRUSTED_GROUP
        self.app_name = 'TestApp'
        self.auth_app = ApplicationFactory(name=self.app_name, user=self.user)


    def test_add_group_command(self):
        """Test AddGroupCommand handle method"""
        add_group = AddGroupCommand()
        add_group.setting_name = 'DEVELOPER_GROUP'
        jwt_oauth2_settings.DEVELOPER_GROUP = None
        self.assertRaises(
            CommandError,
            add_group.handle,
            **{'username': 'TestUser'}
        )

        jwt_oauth2_settings.DEVELOPER_GROUP = 'not_group'
        self.assertRaises(
            CommandError,
            add_group.handle,
            **{'username': 'TestUser'}
        )

        add_group.setting_name = 'TRUSTED_OAUTH_GROUP'
        self.assertRaises(
            CommandError,
            add_group.handle,
            **{'username': 'NotAUser'}
        )

        self.assertNotIn(
            TRUSTED_GROUP, self.user.groups.values_list("name", flat=True)
        )
        add_group.handle(**{'username': 'TestUser'})
        self.assertIn(
            TRUSTED_GROUP, self.user.groups.values_list("name", flat=True)
        )

    def test_skip_auth_command(self):
        skip_auth = SkipAuthCommand()
        skip_auth.skip_auth = True

        self.assertRaises(
            CommandError,
            skip_auth.handle,
            **{
                'username': 'TestUser',
                'app_name': None,
                'app_id': None
            }
        )

        self.assertRaises(
            CommandError,
            skip_auth.handle,
            **{
                'username': 'NotAUser',
                'app_name': self.app_name,
                'app_id': None
            }
        )

        self.assertRaises(
            CommandError,
            skip_auth.handle,
            **{
                'username': 'TestUser',
                'app_name': None,
                'app_id': 99999
            }
        )

        self.assertRaises(
            CommandError,
            skip_auth.handle,
            **{
                'username': 'TestUser',
                'app_name': 'NotApp',
                'app_id': None
            }
        )

        extra_app = ApplicationFactory(name=self.app_name, user=self.user)

        self.assertRaises(
            CommandError,
            skip_auth.handle,
            **{
                'username': 'TestUser',
                'app_name': self.app_name,
                'app_id': None
            }
        )

        self.assertFalse(extra_app.skip_authorization)
        skip_auth.handle(
            **{
                'username': 'TestUser',
                'app_name': None,
                'app_id': extra_app.id
            }
        )
        extra_app = Application.objects.get(id=extra_app.id)
        self.assertTrue(extra_app.skip_authorization)

    def test_add_to_developers(self):
        GroupFactory(name='developers')
        jwt_oauth2_settings.DEVELOPER_GROUP = 'developers'
        out = StringIO()
        call_command('add_to_developers', 'TestUser', stdout=out)
        self.assertIn('to group developers', out.getvalue())

    def test_add_to_trusted(self):
        out = StringIO()
        call_command('add_to_trusted', 'TestUser', stdout=out)
        self.assertIn('to group trusted_developers', out.getvalue())

    def test_allow_skip_authorization(self):
        out = StringIO()
        call_command(
            'allow_skip_authorization', 'TestUser',
            stdout=out, app_id=self.auth_app.id
        )
        self.assertIn('skip_authorization to True', out.getvalue())

    def test_revoke_skip_authorization(self):
        out = StringIO()
        call_command(
            'revoke_skip_authorization', 'TestUser',
            stdout=out, app_id=self.auth_app.id
        )
        self.assertIn('skip_authorization to False', out.getvalue())
