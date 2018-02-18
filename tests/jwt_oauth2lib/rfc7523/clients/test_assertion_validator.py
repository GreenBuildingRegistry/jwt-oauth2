#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage.
All rights reserved
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
import time
from unittest import TestCase

# Local Imports
from jwt_oauth2lib.rfc7523.clients import AssertionValidator


# Tests
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

    def test_validate_nbf(self):
        """Test AssertionValidator validate_nbf method"""
        val = AssertionValidator()
        self.assertTrue(val.validate_nbf(None, 1500046547))

        nbf = time.time()
        exp = nbf + 300
        self.assertTrue(val.validate_nbf(nbf, exp))

        exp = nbf - 300
        self.assertFalse(val.validate_nbf(nbf, exp))

        nbf = 1500046547
        exp = nbf + 300
        self.assertFalse(val.validate_nbf(nbf, exp))

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
