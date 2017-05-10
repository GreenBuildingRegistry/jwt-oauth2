#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2017 Earth Advantage.
All rights reserved
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
from unittest import TestCase

# Local Imports
from jwt_oauth2lib.rfc7523.clients import AssertionValidator


class AssertionValidatorTest(TestCase):
    """Assertion Validator unit tests"""

    def test_validate_required(self):
        """Test AssertionValidator validate_required method"""
        val = AssertionValidator()

        required = ['iss', 'aud', 'sub']
        payload = {'iss': 'iss', 'aud': 'aud'}
        self.assertFalse(val.validate_required(payload, required))

        payload['sub'] = 'sub'
        self.assertTrue(val.validate_required(payload, required))

    def test_method_contracts(self):
        """Test AssertionValidator methods"""
        val = AssertionValidator()

        self.assertRaises(
            NotImplementedError, val.validate_iss,
            'iss'
        )
        self.assertRaises(
            NotImplementedError, val.validate_aud,
            'aud'
        )
        self.assertRaises(
            NotImplementedError, val.validate_sub,
            'sub'
        )
        self.assertRaises(
            NotImplementedError, val.validate_nbf,
            'nbf', 'exp'
        )
        self.assertRaises(
            NotImplementedError, val.validate_jti,
            'jti'
        )
        self.assertRaises(
            NotImplementedError, val.validate_scope,
            'scope'
        )
        self.assertRaises(
            NotImplementedError, val.validate_client_id,
            'client_id'
        )
        self.assertRaises(
            NotImplementedError, val.validate_additional_claims,
            'claims'
        )
