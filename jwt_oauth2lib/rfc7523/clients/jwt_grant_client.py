#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
import logging
import time

# Imports from Third Party Modules
import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_pem_private_key,
)

# Local Imports
from jwt_oauth2lib.rfc7523 import errors
from jwt_oauth2lib.rfc7523.clients.assertion_validator import (
    AssertionValidator
)

log = logging.getLogger(__name__)            # pylint: disable-msg=invalid-name


class JWTGrantClient(object):
    """JWT Grant Request client

    Client for creating and encoding JWT assertions, and preparing access token
    requests per RFC7523 standards.
    .. _`RFC7523`: https://tools.ietf.org/html/rfc7523

    JWTGrantRequest can be subclassed to set defaults for 'validator_class',
    'audience', 'token_scope', 'token_url', and 'expiration_seconds'.
    When using JWTGrantRequest without subclassing, 'audience' and
    'assertion_validator' must be supplied on instantiation.
    """
    _grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
    _crypto_algorithm = 'RS256'
    _required_claims = ['iss', 'sub', 'aud', 'exp']
    _non_required_claims = ['nbf', 'iat', 'jti']
    validator_class = None
    audience = None
    token_scope = None
    expiration_seconds = 300
    token_url = None
    __slots__ = (
        'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'other_claims',
        'scope', 'client_id', 'signature', 'assertion_validator', 'seconds',
        'include_iat'
    )

    def __init__(self, private_key, subject, issuer, audience=None,
                 not_before=None, jwt_id=None, token_scope=None,
                 client_id=None, expiration_seconds=None,
                 include_issued_at=False, pvt_key_password=None,
                 assertion_validator=None, **kwargs):
        self.signature = self._serialize_private_key(
            private_key, pvt_key_password
        )

        self.sub = subject
        self.iss = issuer
        self.aud = audience or getattr(self, 'audience', None)
        self.nbf = not_before
        self.jti = jwt_id
        self.scope = token_scope or getattr(self, 'token_scope', None)
        self.client_id = client_id
        self.include_iat = include_issued_at
        self.seconds = expiration_seconds or self.expiration_seconds
        self.other_claims = kwargs
        self.assertion_validator = assertion_validator or self._get_validator()
        self.iat = None

    def _get_validator(self):
        """Get validator class instance."""
        validator_class = self.validator_class or AssertionValidator
        if validator_class:
            return validator_class()

    def _get_expiration(self, expiration_seconds):
        """Get token expiration (exp) timestamp from current time or 'nbf'."""
        timestamp = time.time()
        if self.nbf:
            timestamp = self.nbf
        return timestamp + expiration_seconds

    @staticmethod
    def _get_issued_at(include_issued_at):
        """Get current timestamp to include as 'iat' claim"""
        iat = None
        if include_issued_at:
            iat = time.time()
        return iat

    @staticmethod
    def _serialize_private_key(private_key, password=None):
        """Cryptographically serialize private key for token signature."""
        error = None
        pvt_key_loaders = [
            load_pem_private_key, load_der_private_key
        ]
        pvt_key = None
        for loader in pvt_key_loaders:
            if not pvt_key:
                try:
                    pvt_key = loader(
                        private_key.encode('utf-8'),
                        password=password,
                        backend=default_backend()
                    )
                    error = False
                    break
                except (ValueError, UnsupportedAlgorithm) as err:
                    error = err
        if error:
            raise errors.InvalidPrivateKeyError(error)
        else:
            return pvt_key

    @property
    def claims_payload(self):
        """Payload dict containing all claims to include in jwt request.

        Expiration and issued at values are generated at the time of
        claims_payload construction to allow recreation of tokens and request
        strings without re-instantiation.
        """
        payload = {
            'iss': self.iss,
            'aud': self.aud,
            'sub': self.sub,
            'exp': self._get_expiration(self.seconds)
        }
        optional_claims = {}
        self.iat = self._get_issued_at(self.include_iat)
        for claim in self._non_required_claims:
            val = getattr(self, claim)
            if val:
                optional_claims[claim] = val
        payload.update(**optional_claims)
        payload.update(**self.other_claims)
        return payload

    @property
    def token(self):
        """Encoded jwt assertion."""
        self.validate_token_claims(self.claims_payload)

        return jwt.encode(
            self.claims_payload, self.signature, self._crypto_algorithm
        ).decode('utf-8')

    @property
    def jwt_request_params(self):
        """
        JWT request string containing grant_type and encoded jwt assertion.
        Scope and client_id are included if applicable.a
        """
        request_params = {
            'grant_type': self._grant_type,
            'assertion': self.token
        }
        if self.scope:                                       # pragma: no cover
            request_params['scope'] = self.scope
        if self.client_id:                                   # pragma: no cover
            request_params['client_id'] = self.client_id
        return request_params

    def validate_token_claims(self, claims):
        """Validate jwt claims and request parameters"""
        if not self.assertion_validator.validate_required(
                claims, self._required_claims
        ):
            log.debug('Missing required claims. %s', claims)
            raise errors.MissingRequiredClaimError(
                description='One or more required claims contained null value',
            )

        if not self.assertion_validator.validate_iss(claims.get('iss')):
            log.debug('Invalid issuer (iss) value. %s', self.iss)
            raise errors.InvalidJWTClaimError(
                description='Issuer (iss) claim contains an invalid value',
            )

        if not self.assertion_validator.validate_sub(claims.get('sub')):
            log.debug('Invalid subject (sub) value. %s', self.sub)
            raise errors.InvalidJWTClaimError(
                description='Subject (sub) claim contains an invalid value',
            )

        if not self.assertion_validator.validate_aud(claims.get('aud')):
            log.debug('Invalid audience (aud) value. %s', self.aud)
            raise errors.InvalidJWTClaimError(
                description='Audience (aud) claim contains an invalid value',
            )

        if not self.assertion_validator.validate_nbf(
                claims.get('nbf'), claims.get('exp')
        ):
            log.debug('Invalid not_before (nbf) value. %s', self.nbf)
            raise errors.InvalidJWTClaimError(
                description='Not Before (nbf) claim contains an invalid value',
            )

        if not self.assertion_validator.validate_jti(claims.get('jti')):
            log.debug('Invalid JWT ID (jti) value. %s', self.jti)
            raise errors.InvalidJWTClaimError(
                description='JWT ID (jti) claim contains an invalid value',
            )

        if not self.assertion_validator.validate_client_id(self.client_id):
            log.debug('Invalid client_id value. %s', self.client_id)
            raise errors.InvalidRequestParameterError(
                description='client_id parameter contains an invalid value',
            )

        if not self.assertion_validator.validate_scope(self.scope):
            log.debug('Invalid scope value. %s', self.scope)
            raise errors.InvalidRequestParameterError(
                description='scope parameter contains an invalid value',
            )

        if not self.assertion_validator.validate_additional_claims(claims):
            log.debug(
                'One or more additional claims contain invalid values. %s',
                self.other_claims
            )
            raise errors.InvalidJWTClaimError(
                description='Additional claims contain invalid values',
            )

    def get_access_token(self, *args, **kwargs):
        """Retrieve access_token from provider using JWT Grant flow."""
        raise NotImplementedError('Subclasses must implement this method.')

    def _check_token_response(self, response, *args, **kwargs):
        """Validate access token response from JWT Grant flow provider."""
        raise NotImplementedError('Subclasses must implement this method.')
