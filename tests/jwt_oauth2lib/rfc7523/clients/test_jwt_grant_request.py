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
import mock

# Local Imports
from jwt_oauth2lib.rfc7523.clients import JWTGrantClient
from jwt_oauth2lib.rfc7523.clients import AssertionValidator
from jwt_oauth2lib.rfc7523.errors import (
    InvalidPrivateKeyError,
    InvalidJWTClaimError,
    InvalidRequestParameterError,
    MissingRequiredClaimError
)
from tests.helpers.fake_token import PRIVATE_KEY_PEM


# Helper Functions & Classes
class MockValidator(AssertionValidator):
    pass


class MockJWTGrantClient(JWTGrantClient):
    audience = 'host',
    validator_class = MockValidator


# Tests
class JWTGrantClientTests(TestCase):
    """JWTGrantClient methods unit tests"""

    def setUp(self):
        """setUp"""
        self.token = MockJWTGrantClient(
            PRIVATE_KEY_PEM, 'resource_owner', 'ert@#cvbn$%d',
            include_issued_at=True
        )

    def test_get_validator(self):
        """Test _get_validator"""
        validator = self.token._get_validator()
        self.assertIsInstance(validator, MockValidator)

    def test_get_expiration(self):
        """Test _get_expiration"""
        seconds = 300
        time_now = time.time()
        exp = self.token._get_expiration(seconds)
        self.assertGreaterEqual(exp, time_now + seconds)

        nbf = 1500046547
        nbf_token = MockJWTGrantClient(
            PRIVATE_KEY_PEM, 'resource_owner', 'ert@#cvbn$%d', not_before=nbf
        )
        exp = nbf_token._get_expiration(seconds)
        self.assertEqual(exp, nbf + seconds)

    def test_get_issued_at(self):
        """Test _get_issued_at"""
        iat = self.token._get_issued_at(True)
        self.assertAlmostEqual(iat, time.time(), 1)

        iat = self.token._get_issued_at(False)
        self.assertIsNone(iat)

    @mock.patch(
        'jwt_oauth2lib.rfc7523.clients.jwt_grant_client.load_pem_private_key'
    )
    def test_serialize_private_key(self, mock_load_key):
        """Test _serialize_private_key"""
        mock_load_key.return_value = 'serialized key'
        self.token._serialize_private_key(PRIVATE_KEY_PEM)
        self.assertTrue(mock_load_key.called)

        mock_load_key.side_effect = ValueError()
        self.assertRaises(
            InvalidPrivateKeyError,
            self.token._serialize_private_key,
            PRIVATE_KEY_PEM
        )

    @mock.patch.object(JWTGrantClient, '_get_issued_at')
    @mock.patch.object(JWTGrantClient, '_get_expiration')
    def test_claims_payload(self, mock_exp, mock_iat):
        """Test claims_payload property method"""
        time_now = time.time()
        mock_iat.return_value = time_now
        mock_exp.return_value = time_now + 300
        required_claims = ['iss', 'sub', 'aud', 'exp']
        claims = self.token.claims_payload
        for claim in required_claims:
            self.assertIn(claim, claims)

        self.assertIn('iat', claims)
        self.assertNotIn('nbf', claims)

        mock_iat.return_value = None
        claims = self.token.claims_payload
        self.assertNotIn('iat', claims)

    @mock.patch.object(JWTGrantClient, 'validate_token_claims')
    @mock.patch('jwt_oauth2lib.rfc7523.clients.jwt_grant_client.jwt.encode')
    def test_token(self, mock_encode, mock_validate):
        """Test token property method"""
        with mock.patch(
            'jwt_oauth2lib.rfc7523.clients.jwt_grant_client.JWTGrantClient.claims_payload',  # noqa
            new_callable=mock.PropertyMock
        ) as mock_payload:
            mock_validate.return_value = True
            mock_payload.return_value = {
                'iss': 'ert@#cvbn$%d',
                'aud': 'host',
                'sub': 'resource_owner',
                'exp': time.time()
            }
            mock_encode.return_value = b"qwertyu@#ertyui^&*cvbnm@#$zxnwertyucv"
            token = self.token.token
            self.assertTrue(mock_payload.called)
            mock_validate.assert_called_with(mock_payload.return_value)
            self.assertTrue(mock_encode.called)
            self.assertEqual(mock_encode.return_value.decode('utf-8'), token)

    @mock.patch.object(JWTGrantClient, 'token')
    def test_jwt_request_params(self, mock_token):
        """Test jwt_request_params property method"""
        mock_token.return_value = 'wert#$sdfgxcvb@dfghj^fghjkl!zxcvbn*ert'
        request_string = self.token.jwt_request_params
        self.assertIn('grant_type', request_string)
        self.assertIn('assertion', request_string)

    def test_validate_token_claims(self):
        """Test validate_token_claims"""
        mock_validator = mock.MagicMock()
        jwt_token = JWTGrantClient(
            PRIVATE_KEY_PEM, 'resource_owner', 'ert@#cvbn$%d',
            assertion_validator=mock_validator
        )

        mock_validator.validate_required.return_value = False
        self.assertRaises(
            MissingRequiredClaimError,
            jwt_token.validate_token_claims, {}
        )
        self.assertFalse(mock_validator.validate_iss.called)

        mock_validator.validate_required.return_value = True
        mock_validator.validate_iss.return_value = False
        self.assertRaises(
            InvalidJWTClaimError,
            jwt_token.validate_token_claims, {}
        )
        self.assertFalse(mock_validator.validate_sub.called)

        mock_validator.validate_iss.return_value = True
        mock_validator.validate_sub.return_value = False
        self.assertRaises(
            InvalidJWTClaimError,
            jwt_token.validate_token_claims, {}
        )
        self.assertFalse(mock_validator.validate_aud.called)

        mock_validator.validate_sub.return_value = True
        mock_validator.validate_aud.return_value = False
        self.assertRaises(
            InvalidJWTClaimError,
            jwt_token.validate_token_claims, {}
        )
        self.assertFalse(mock_validator.validate_nbf.called)

        mock_validator.validate_aud.return_value = True
        mock_validator.validate_nbf.return_value = False
        self.assertRaises(
            InvalidJWTClaimError,
            jwt_token.validate_token_claims, {}
        )
        self.assertFalse(mock_validator.validate_jti.called)

        mock_validator.validate_nbf.return_value = True
        mock_validator.validate_jti.return_value = False
        self.assertRaises(
            InvalidJWTClaimError,
            jwt_token.validate_token_claims, {}
        )
        self.assertFalse(mock_validator.validate_client_id.called)

        mock_validator.validate_jti.return_value = True
        mock_validator.validate_client_id.return_value = False
        self.assertRaises(
            InvalidRequestParameterError,
            jwt_token.validate_token_claims, {}
        )
        self.assertFalse(mock_validator.validate_scope.called)

        mock_validator.validate_client_id.return_value = True
        mock_validator.validate_scope.return_value = False
        self.assertRaises(
            InvalidRequestParameterError,
            jwt_token.validate_token_claims, {}
        )
        self.assertFalse(mock_validator.validate_additional_claims.called)

        mock_validator.validate_scope.return_value = True
        mock_validator.validate_additional_claims.return_value = False
        self.assertRaises(
            InvalidJWTClaimError,
            jwt_token.validate_token_claims, {}
        )

        mock_validator.validate_additional_claims.return_value = True
        self.assertIsNone(jwt_token.validate_token_claims({}))

    def test_abstract_methods(self):
        """Test methods that require subclassing"""

        self.assertRaises(NotImplementedError, self.token.get_access_token)
        self.assertRaises(
            NotImplementedError, self.token._check_token_response,
            'response'
        )
