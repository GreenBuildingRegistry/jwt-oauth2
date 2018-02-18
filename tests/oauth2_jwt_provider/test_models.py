#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
from datetime import datetime

# Imports from Django
from django.contrib.auth import get_user_model
from django.test import TransactionTestCase

# Imports from Third Party Modules
import mock
import pytz
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from oauth2_provider.models import get_application_model

# Local Imports
from oauth2_jwt_provider.models import PublicKey
from oauth2_jwt_provider.settings import jwt_oauth2_settings
from tests.helpers.fake_token import PUBLIC_KEY_PEM, PUBLIC_KEY_SSH

UserModel = get_user_model()
Application = get_application_model()


class TestPublicKeyModel(TransactionTestCase):
    """oauth_jwt_provider PublicKey model unit tests"""

    def setUp(self):
        """setUp"""
        user = UserModel.objects.create_user("user", "test@user.com", "123456")
        self.application = Application.objects.create(
            client_id='client_id', client_secret='client_secret',
            user=user, client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE
        )
        self.pub_key = PublicKey.objects.create(
            application=self.application, key=PUBLIC_KEY_PEM
        )

    def tearDown(self):
        self.application.delete()

    def test_init(self):
        """Test PublicKey.__init__ method"""
        pub_key = PublicKey.objects.get(application=self.application)
        self.assertEqual(pub_key._PublicKey__original_key, pub_key._key)
        pub_key._key = 'new key'
        self.assertNotEqual(pub_key._PublicKey__original_key, pub_key._key)

    def test_save(self):
        """Test PublicKey.save method"""
        pub_key_date = self.pub_key.pub_key_last_updated
        self.pub_key.save()
        self.assertEqual(self.pub_key.pub_key_last_updated, pub_key_date)

        self.pub_key.key = PUBLIC_KEY_SSH
        self.pub_key.save()
        self.assertGreater(self.pub_key.pub_key_last_updated, pub_key_date)

    def test_key(self):
        """Test PublicKey.key property method"""
        with mock.patch('oauth2_jwt_provider.models.PublicKey.is_expired',
                        new_callable=mock.PropertyMock) as mock_is_expired:
            mock_is_expired.return_value = False
            result = self.pub_key.key
            self.assertIsNotNone(result)
            self.assertIsInstance(result, _RSAPublicKey)

            self.pub_key.key = PUBLIC_KEY_SSH
            self.pub_key.save()
            result = self.pub_key.key
            self.assertIsNotNone(result)
            self.assertIsInstance(result, _RSAPublicKey)

            mock_is_expired.return_value = True
            result = self.pub_key.key
            self.assertIsNone(result)

    def test_is_expired(self):
        """Test PublicKey.is_expired property method"""
        jwt_oauth2_settings.PUBLIC_KEY_EXPIRE_DAYS = None
        self.assertFalse(self.pub_key.is_expired)

        jwt_oauth2_settings.PUBLIC_KEY_EXPIRE_DAYS = 90
        self.assertFalse(self.pub_key.is_expired)

        self.pub_key.pub_key_last_updated = pytz.utc.localize(
            datetime(2016, 1, 1)
        )
        self.pub_key.save()
        self.assertTrue(self.pub_key.is_expired)
