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
from django.core.exceptions import ValidationError

# Local Imports
from oauth2_jwt_provider.validators import validate_public_key
from tests.helpers.fake_token import PUBLIC_KEY_PEM, PUBLIC_KEY_SSH


class TestModelValidators(TestCase):
    """Unit Tests for oauth2_jwt_provider model validators"""

    def test_validate_public_key(self):
        """Test validate_public_key"""
        not_a_key = 'asdfghjkl;qwertyuiopzxcvbnm.qwertyuiopasdfghjkzxcvbn'
        looks_like_a_key = '''
        -----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBCeVu627zFZ1JH9/Wi/J/bs6z
        C3bUFl0ASfE6XHGxyPTAPXgJnc7AsnRBxbNA692v1srkZr1X1BwUbzcaMRZwpGi4
        vO4VwzLldJC/YLFp5z6C66bgGvRrp5pQhu4ntuHR82yS2X/IBsmMArUug9mO
        -----END PUBLIC KEY-----
        '''

        self.assertRaises(
            ValidationError, validate_public_key, not_a_key
        )
        self.assertRaises(
            ValidationError, validate_public_key, looks_like_a_key
        )
        validate_public_key(PUBLIC_KEY_PEM)
        validate_public_key(PUBLIC_KEY_SSH)
