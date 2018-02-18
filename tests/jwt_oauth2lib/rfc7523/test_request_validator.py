#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
from unittest import TestCase

# Local Imports
from jwt_oauth2lib.rfc7523.request_validator import RequestValidator


class RequestValidatorTest(TestCase):
    """Request Validator unit tests"""

    def test_method_contracts(self):
        """Test RequestValidator methods"""
        val = RequestValidator()
        self.assertRaises(
            NotImplementedError, val.get_audience,
            'request'
        )
        self.assertRaises(
            NotImplementedError, val.validate_issuer,
            'request', 'token'
        )
        self.assertRaises(
            NotImplementedError, val.validate_signature,
            'request', 'client', 'token'
        )
        self.assertRaises(
            NotImplementedError, val.validate_subject,
            'request', 'client', 'payload'
        )
        self.assertRaises(
            NotImplementedError, val.validate_offline_access,
            'request', 'user', 'client'
        )
        self.assertRaises(
            NotImplementedError, val.validate_refresh_scopes,
            'request', ['prior tokens'], ['scope']
        )
        self.assertTrue(val.validate_additional_claims('request', 'payload'))
