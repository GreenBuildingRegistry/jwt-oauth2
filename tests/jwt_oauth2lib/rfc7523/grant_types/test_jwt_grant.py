#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
import json
from unittest import TestCase

# Imports from Third Party Modules
import mock
from oauthlib.common import Request
from oauthlib.oauth2 import BearerToken
from oauthlib.oauth2.rfc6749 import errors

# Local Imports
from jwt_oauth2lib.rfc7523.grant_types import JWTGrant
from tests.helpers import FakeToken


class JWTGrantTest(TestCase):
    """JWTGrant methods unit tests"""

    def setUp(self):
        """setUp"""
        self.mock_path = 'http://localhost/path'
        self.mock_user = "mocked user"
        self.mock_client_id = "rsF9VmpTd"
        mock_client = mock.MagicMock()
        mock_client.user.return_value = self.mock_user
        self.assertion = FakeToken(
            aud=self.mock_path, sub=self.mock_user, iss=self.mock_client_id
        )
        self.grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        self.request = Request(self.mock_path)
        self.mock_validator = mock.MagicMock()
        self.auth = JWTGrant(
            request_validator=self.mock_validator, audience=self.mock_path
        )

    @mock.patch.object(JWTGrant, 'validate_token_request')
    def test_create_token_response_fail(self, mock_validate_token):
        """Test create_token_response with failing validation"""
        mock_validate_token.side_effect = errors.OAuth2Error()
        bearer = BearerToken(self.mock_validator)
        headers, body, status_code = self.auth.create_token_response(
            self.request, bearer
        )
        self.assertNotEqual(status_code, 200)
        self.assertIn('error', body)

    @mock.patch.object(JWTGrant, 'validate_token_request')
    def test_create_token_response_pass(self, mock_validate_token):
        """Test create_token_response with passing validation"""
        mock_validate_token.return_value = None
        bearer = BearerToken(self.mock_validator)
        headers, body, status_code = self.auth.create_token_response(
            self.request, bearer
        )
        token = json.loads(body)
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', token)
        self.assertIn('token_type', token)
        self.assertIn('expires_in', token)

    def test_validate_token_request(self):
        """Test validate_token_request for required request attributes."""
        with self.assertRaises(errors.UnsupportedGrantTypeError):
            self.request.grant_type = "refresh_token"
            self.auth.validate_token_request(self.request)

        self.request.grant_type = self.grant_type
        with self.assertRaises(errors.InvalidRequestError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'Missing jwt assertion parameter.'
        self.assertIn(expected, err.exception.args[0])

        self.request.assertion = "{0},{0}".format(self.assertion.token)
        with self.assertRaises(errors.InvalidRequestError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'Assertion MUST NOT contain more than one JWT'
        self.assertIn(expected, err.exception.args[0])

    def test_validate_jwt_required_claims(self):
        """Test validate_token_request for required request jwt claims."""
        self.mock_validator.get_audience.return_value = self.mock_path
        self.request.grant_type = self.grant_type

        bad_exp = FakeToken(
            aud=self.mock_path, sub=self.mock_user, iss=self.mock_client_id,
            exp="1490498853"
        )
        self.request.assertion = bad_exp.token
        with self.assertRaises(errors.InvalidGrantError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'JWT request contains an expired signature'
        self.assertIn(expected, err.exception.args[0])

        immature = FakeToken(
            aud=self.mock_path, sub=self.mock_user, iss=self.mock_client_id,
            nbf="2745532800"
        )
        self.request.assertion = immature.token
        with self.assertRaises(errors.InvalidGrantError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'JWT is not yet valid (nbf)'
        self.assertIn(expected, err.exception.args[0])

        bad_aud = FakeToken(
            aud='', sub=self.mock_user, iss=self.mock_client_id,
        )
        self.request.assertion = bad_aud.token
        with self.assertRaises(errors.InvalidGrantError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'JWT request contains invalid audience claim'
        self.assertIn(expected, err.exception.args[0])

        required_claims = FakeToken(
            aud=self.mock_path, sub=self.mock_user, iss=self.mock_client_id,
            exp=None
        )
        self.request.assertion = required_claims.token
        with self.assertRaises(errors.InvalidGrantError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'JWT is missing a required claim'
        self.assertIn(expected, err.exception.args[0])

        self.request.assertion = ''
        with self.assertRaises(errors.InvalidGrantError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'One of more errors occurred during JWT decode'
        self.assertIn(expected, err.exception.args[0])

    def test_validator_handling(self):
        """Test validate_token_request for jwt claims validation."""
        self.mock_validator.get_audience.return_value = self.mock_path
        self.request.grant_type = self.grant_type
        self.request.assertion = self.assertion.token
        self.mock_validator.validate_issuer.return_value = False
        with self.assertRaises(errors.InvalidGrantError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'Missing or invalid (iss) claim'
        self.assertIn(expected, err.exception.args[0])

        self.mock_validator.validate_issuer.return_value = True

        self.mock_validator.validate_client_id.return_value = False
        with self.assertRaises(errors.InvalidClientError):
            self.auth.validate_token_request(self.request)

        self.mock_validator.validate_client_id.return_value = True

        self.mock_validator.validate_signature.return_value = False
        with self.assertRaises(errors.InvalidGrantError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'Missing or invalid token signature'
        self.assertIn(expected, err.exception.args[0])

        self.mock_validator.validate_signature.return_value = True

        self.mock_validator.validate_subject.return_value = False
        with self.assertRaises(errors.InvalidGrantError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'Missing or invalid (sub) claim'
        self.assertIn(expected, err.exception.args[0])

        self.mock_validator.validate_subject.return_value = True

        self.mock_validator.validate_offline_access.return_value = False
        with self.assertRaises(errors.InvalidGrantError) as err:
            self.auth.validate_token_request(self.request)
        expected = 'Client not authorized for offline_access grants'
        self.assertIn(expected, err.exception.args[0])

        self.mock_validator.validate_offline_access.return_value = True

        self.mock_validator.validate_refresh_scopes.return_value = False
        with self.assertRaises(errors.InvalidScopeError):
            self.auth.validate_token_request(self.request)

        self.mock_validator.validate_refresh_scopes.return_value = True

        self.mock_validator.validate_additional_claims.return_value = False
        with self.assertRaises(errors.InvalidGrantError):
            self.auth.validate_token_request(self.request)

    def test_custom_token_validators(self):
        """Test validate_token_request for pre & post token validators."""
        self.mock_validator.get_audience.return_value = self.mock_path
        self.request.grant_type = self.grant_type
        self.request.assertion = self.assertion.token
        tknval1, tknval2 = mock.Mock(), mock.Mock()
        self.auth.custom_validators.pre_token.append(tknval1)
        self.auth.custom_validators.post_token.append(tknval2)

        bearer = BearerToken(self.mock_validator)
        self.auth.create_token_response(self.request, bearer)
        self.assertTrue(tknval1.called)
        self.assertTrue(tknval2.called)
