#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
import unittest

# Imports from Django
from django.core.exceptions import ImproperlyConfigured

# Imports from Third Party Modules
import mock

# Local Imports
from oauth2_jwt_provider.models import PublicKey
from oauth2_jwt_provider.oauth2_validators import OAuth2Validator
from oauth2_jwt_provider.settings import (
    OAuth2JWTProviderSettings,
    import_from_string,
    perform_import,
)


class TestSettingsFunctions(unittest.TestCase):
    """Units tests for Settings funtions and methods"""

    @mock.patch('oauth2_jwt_provider.settings.import_from_string')
    def test_perform_import(self, mock_string_import):
        """Test settings perform_import"""
        self.assertRaises(
            ImproperlyConfigured,
            perform_import,
            'not_a_setting', 'SETTING',
        )
        self.assertRaises(
            ImproperlyConfigured,
            perform_import,
            ('bad_value', 'module.path.AnotherClass'), 'SETTING',
        )

        mock_string_import.return_value = 'Class'
        result = perform_import('module.path.Class', 'SETTING')
        self.assertEqual(result, mock_string_import.return_value)

        list_return = ['Class', 'AnotherClass']
        mock_string_import.side_effect = list_return
        result = perform_import(
            ('module.path.Class', 'module.path.AnotherClass'), 'SETTING'
        )
        self.assertListEqual(result, list_return)

    def test_import_from_string(self):
        """Test settings import_from_string"""
        expected = OAuth2Validator
        class_str = 'oauth2_jwt_provider.oauth2_validators.OAuth2Validator'
        result = import_from_string(class_str, 'SETTING')
        self.assertEqual(result, expected)
        mock_import = mock.MagicMock()
        with mock.patch(
                'oauth2_jwt_provider.settings.importlib.import_module',
                mock_import
        ):
            import_from_string(class_str, 'SETTING')
            mock_import.assert_called()

        expected = PublicKey
        class_str = 'oauth2_jwt_provider.PublicKey'
        result = import_from_string(class_str, 'SETTING')
        self.assertEqual(result, expected)
        mock_model_import = mock.MagicMock()
        with mock.patch(
                'oauth2_jwt_provider.settings.apps.get_model',
                mock_model_import
        ):
            import_from_string(class_str, 'SETTING')
            mock_model_import.assert_called()

        self.assertRaises(
            ImportError,
            perform_import,
            'module.path.NotAClass', 'SETTING',
        )


class TestOAuth2JWTProviderSettings(unittest.TestCase):
    """Unit tests for OAuth2JWTProviderSettings methods"""

    def setUp(self):
        """setUp"""
        self.mock_string_class = 'module.path.Class'
        self.test_user_settings = {
            'USER_OVERRIDE_SETTING': 'user_value',
            'SHARED_DOT_JWT_USER_SETTING': 'jwt_user_value'
        }
        self.test_defaults = {
            'JWT_SETTING': None,
            'USER_OVERRIDE_SETTING': 'default_value',
            'SHARED_DOT_SETTING': 'jwt_dot_default',
            'SHARED_DOT_JWT_USER_SETTING': 'jwt_default',
            'SHARED_DOT_USER_SETTING': 'jwt_dot_default',
            'STRING_SETTING': self.mock_string_class
        }
        test_strings = ('STRING_SETTING',)
        test_mandatory = ('JWT_SETTING',)
        self.test_dot_user_settings = {
            'SHARED_DOT_JWT_USER_SETTING': 'dot_user_value',
            'SHARED_DOT_USER_SETTING': 'jwt_dot_user_value'
        }
        test_dot_settings = (
            'SHARED_DOT_SETTING',
            'SHARED_DOT_JWT_USER_SETTING',
            'SHARED_DOT_USER_SETTING',
        )
        self.test_settings = OAuth2JWTProviderSettings(
            self.test_user_settings, self.test_defaults, test_strings,
            test_mandatory, self.test_dot_user_settings, test_dot_settings
        )

    @mock.patch.object(OAuth2JWTProviderSettings, 'validate_setting')
    @mock.patch('oauth2_jwt_provider.settings.perform_import')
    def test_get_attr(self, mock_import, mock_validate):
        """Test setting class get_attr method"""
        mock_validate.return_value = None
        mock_import.return_value = 'Class'
        with self.assertRaises(AttributeError) as err:
            self.test_settings.__getattr__('NOT_A_SETTING')
        self.assertIn('Invalid OAuth2JWTProvider setting',
                      err.exception.args[0])

        # priority to user settings
        expected = self.test_user_settings['USER_OVERRIDE_SETTING']
        not_expected = self.test_defaults['USER_OVERRIDE_SETTING']
        result = self.test_settings.__getattr__('USER_OVERRIDE_SETTING')
        self.assertEqual(result, expected)
        self.assertNotEqual(result, not_expected)

        # priority to dot user settings over default
        expected = self.test_dot_user_settings['SHARED_DOT_USER_SETTING']
        not_expected = self.test_defaults['SHARED_DOT_USER_SETTING']
        result = self.test_settings.__getattr__('SHARED_DOT_USER_SETTING')
        self.assertEqual(result, expected)
        self.assertNotEqual(result, not_expected)

        # priority to jwt user over dot user
        expected = self.test_user_settings['SHARED_DOT_JWT_USER_SETTING']
        not_expected = self.test_dot_user_settings['SHARED_DOT_JWT_USER_SETTING']
        result = self.test_settings.__getattr__('SHARED_DOT_JWT_USER_SETTING')
        self.assertEqual(result, expected)
        self.assertNotEqual(result, not_expected)

        # priority to default stays if no dot USER setting
        expected = self.test_defaults['SHARED_DOT_SETTING']
        not_expected = self.test_dot_user_settings.get('SHARED_DOT_SETTING')
        result = self.test_settings.__getattr__('SHARED_DOT_SETTING')
        self.assertEqual(result, expected)
        self.assertNotEqual(result, not_expected)

        # string conversion
        expected = mock_import.return_value = 'Class'
        result = self.test_settings.__getattr__('STRING_SETTING')
        self.assertEqual(result, expected)

    def test_validate_setting(self):
        """Test setting class validate_setting method"""
        with self.assertRaises(AttributeError) as err:
            self.test_settings.validate_setting('JWT_SETTING', None)
        self.assertIn('is mandatory', err.exception.args[0])
