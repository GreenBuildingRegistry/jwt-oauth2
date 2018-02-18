#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
import time
from datetime import datetime

# Imports from Django
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import TransactionTestCase

# Imports from Third Party Modules
import mock
from oauth2_provider.models import (
    AccessToken,
    RefreshToken,
    get_application_model,
)
from oauth2_provider.settings import oauth2_settings
from oauthlib.common import Request

# Local Imports
from oauth2_jwt_provider.models import PublicKey
from oauth2_jwt_provider.oauth2_validators import OAuth2Validator
from oauth2_jwt_provider.settings import jwt_oauth2_settings
from tests.helpers.fake_token import PUBLIC_KEY_PEM, PUBLIC_KEY_SSH, FakeToken
from tests.models import NonUniqueIssuer

UserModel = get_user_model()
Application = get_application_model()


class TestOAuth2Validator(TransactionTestCase):
    def setUp(self):
        """setUp"""
        self.mock_path = 'http://localhost/path'
        jwt_oauth2_settings.JWT_AUDIENCE = self.mock_path
        self.user = UserModel.objects.create_user(
            "user", "test@user.com", "123456"
        )
        self.application = Application.objects.create(
            client_id='client_id', client_secret='client_secret',
            user=self.user, client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE
        )
        self.mock_path = 'http://localhost/path'
        self.token = FakeToken(
            aud=self.mock_path, sub=self.user.username,
            iss=self.application.client_id
        )
        self.assertion = self.token.token
        self.grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        self.request = Request(self.mock_path)
        self.validator = OAuth2Validator()
        self.request.client = self.application

    def tearDown(self):
        """tearDown"""
        self.application.delete()

    def test_get_audience(self):
        """Test get_audience"""
        self.assertEqual(
            jwt_oauth2_settings.JWT_AUDIENCE,
            self.validator.get_audience(self.request, )
        )

    def test_validate_issuer(self):
        """Test validate_issuer"""
        token_payload = {
        }
        result = self.validator.validate_issuer(self.request, token_payload)
        self.assertFalse(result)

        token_payload['iss'] = 'unmatched issuer'
        result = self.validator.validate_issuer(self.request, token_payload)
        self.assertFalse(result)

        token_payload['iss'] = 'client_id'
        result = self.validator.validate_issuer(self.request, token_payload)
        self.assertTrue(result)

        non_unique = 'non unique issuer'
        NonUniqueIssuer.objects.create(non_unique_id=non_unique)
        NonUniqueIssuer.objects.create(non_unique_id=non_unique)
        jwt_oauth2_settings.ISSUER_IDENTIFIER_MODEL = NonUniqueIssuer
        jwt_oauth2_settings.ISSUER_IDENTIFIER_ATTR = 'non_unique_id'
        token_payload['iss'] = non_unique
        self.assertRaises(
            ImproperlyConfigured, self.validator.validate_issuer,
            self.request,
            token_payload
        )

    def test_validate_signature(self):
        """Test validate_signature"""
        result = self.validator.validate_signature(
            self.request, self.request.client, self.assertion
        )
        self.assertFalse(result)

        pub_key = PublicKey.objects.create(
            application=self.application, key=PUBLIC_KEY_SSH
        )
        result = self.validator.validate_signature(
            self.request, self.request.client, self.assertion
        )
        self.assertFalse(result)

        pub_key.key = PUBLIC_KEY_PEM
        pub_key.save()
        result = self.validator.validate_signature(
            self.request, self.request.client, self.assertion
        )
        self.assertTrue(result)

    def test_validate_subject(self):
        """Test validate_subject"""
        token_payload = {
        }
        result = self.validator.validate_subject(
            self.request, self.request.client, token_payload
        )
        self.assertFalse(result)

        token_payload = {
            'sub': 'not a user'
        }
        result = self.validator.validate_subject(
            self.request, self.request.client, token_payload
        )
        self.assertFalse(result)

        token_payload = {
            'sub': 'user'
        }
        result = self.validator.validate_subject(
            self.request, self.request.client, token_payload
        )
        self.assertTrue(result)

        self.application.authorization_grant_type = (
            Application.GRANT_CLIENT_CREDENTIALS
        )
        self.application.save()
        token_payload = {
            'sub': 'user'
        }
        result = self.validator.validate_subject(
            self.request, self.request.client, token_payload
        )
        self.assertFalse(result)
        token_payload = {
            'sub': 'client_id'
        }
        result = self.validator.validate_subject(
            self.request, self.request.client, token_payload
        )
        self.assertTrue(result)

        self.user.is_active = False
        self.user.save()
        token_payload = {
            'sub': 'client_id'
        }
        result = self.validator.validate_subject(
            self.request, self.request.client, token_payload
        )
        self.assertFalse(result)

    def test_validate_offline_access(self):
        """Test validate_offline_access"""
        access_token = AccessToken.objects.create(
            user=self.user,
            scope='read write',
            expires=datetime(2099, 1, 1),
            token='',
            application=self.application
        )
        # by scope
        result = self.validator.validate_offline_access(
            self.request, self.user, self.request.client, by_scope=True
        )
        self.assertFalse(result)

        self.application.skip_authorization = True
        self.application.save()
        result = self.validator.validate_offline_access(
            self.request, self.user, self.request.client, by_scope=True
        )
        self.assertTrue(result)

        oauth2_settings._SCOPES = ["read", "write"]
        result = self.validator.validate_offline_access(
            self.request, self.user, self.request.client, by_scope=True
        )
        self.assertFalse(result)

        # by refresh tokens
        RefreshToken.objects.create(
            user=self.user,
            application=self.application,
            access_token=access_token,
            token=''
        )
        result = self.validator.validate_offline_access(
            self.request, self.user, self.request.client, by_scope=False
        )
        self.assertTrue(result)

        tokenless_user = UserModel.objects.create_user('tokenless_user')
        result = self.validator.validate_offline_access(
            self.request, tokenless_user, self.request.client, by_scope=False
        )
        self.assertFalse(result)

        # client credentials app
        self.application.authorization_grant_type = (
            Application.GRANT_CLIENT_CREDENTIALS
        )
        self.application.save()
        result = self.validator.validate_offline_access(
            self.request, self.user, self.request.client, by_scope=False
        )
        self.assertTrue(result)

    def test_validate_refresh_scopes(self):
        """Test validate_refresh_scopes"""
        access_token = AccessToken.objects.create(
            user=self.user,
            scope='read write',
            expires=datetime(2099, 1, 1),
            token='12345',
            application=self.application
        )
        refresh_token1 = RefreshToken.objects.create(
            user=self.user,
            application=self.application,
            access_token=access_token,
            token='54321'
        )
        access_token = AccessToken.objects.create(
            user=self.user,
            scope='read scope1',
            expires=datetime(2099, 1, 1),
            token='67890',
            application=self.application
        )
        refresh_token2 = RefreshToken.objects.create(
            user=self.user,
            application=self.application,
            access_token=access_token,
            token='09876'
        )

        oauth2_settings._SCOPES = ["read", "write", "offline", "scope1"]
        result = self.validator.validate_refresh_scopes(
            self.request, [refresh_token1, refresh_token2], 'read'
        )
        self.assertTrue(result)

        result = self.validator.validate_refresh_scopes(
            self.request, [refresh_token1, refresh_token2], 'write scope1'
        )
        self.assertTrue(result)

        result = self.validator.validate_refresh_scopes(
            self.request, [refresh_token1, refresh_token2], None
        )
        self.assertTrue(result)

        result = self.validator.validate_refresh_scopes(
            self.request, None, 'offline'
        )
        self.assertTrue(result)

        result = self.validator.validate_refresh_scopes(
            self.request, None, None
        )
        self.assertTrue(result)

        result = self.validator.validate_refresh_scopes(
            self.request, [refresh_token1, refresh_token2], 'offline'
        )
        self.assertFalse(result)

        result = self.validator.validate_refresh_scopes(
            self.request, None, "scope2"
        )
        self.assertFalse(result)

    @mock.patch.object(OAuth2Validator, '_validate_max_exp')
    def test_validate_additional_claims(self, mock_valid_max_exp):
        """Test validate_additional_claims"""
        payload = {'exp': time.time()}
        mock_valid_max_exp.return_value = True
        self.assertTrue(
            self.validator.validate_additional_claims(self.request, payload)
        )

        mock_valid_max_exp.return_value = False
        self.assertFalse(
            self.validator.validate_additional_claims(self.request, payload)
        )

    def test_validate_max_exp(self):
        jwt_oauth2_settings.JWT_MAX_EXPIRE_SECONDS = 300
        jwt_oauth2_settings.TIME_SKEW_ALLOWANCE_SECONDS = 10
        exp = time.time() + 250
        self.assertTrue(self.validator._validate_max_exp(exp))

        exp = time.time() + 3000
        self.assertFalse(self.validator._validate_max_exp(exp))

        jwt_oauth2_settings.JWT_MAX_EXPIRE_SECONDS = None
        jwt_oauth2_settings.TIME_SKEW_ALLOWANCE_SECONDS = None
        self.assertTrue(self.validator._validate_max_exp(exp))
