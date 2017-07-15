#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2017 Earth Advantage. All rights reserved.
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

log = logging.getLogger(__name__)  # pylint: disable-msg=invalid-name


class JWTGrantRequest(object):
    _grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
    _crypto_algorithm = 'RS256'
    _required_claims = ['iss', 'sub', 'aud', 'exp']
    _non_required_claims = ['nbf', 'iat', 'jti']
    __slots__ = (
        'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'other_claims',
        'scope', 'client_id', 'signature', 'assertion_validator'
    )

    def __init__(self, private_key, subject, issuer=None, audience=None,
                 not_before=None, jwt_id=None, scope=None, client_id=None,
                 expiration_seconds=300, include_issued_at=False,
                 pvt_key_password=None, assertion_validator=None, **kwargs):
        self.signature = self._serialize_private_key(
            private_key, pvt_key_password
        )

        self.sub = subject
        self.iss = issuer or self.iss
        self.aud = audience or self.aud
        self.nbf = not_before or self.nbf
        self.jti = jwt_id or self.jti
        self.scope = scope or self.scope
        self.client_id = client_id or self.client_id
        self.iat = self._get_issued_at(include_issued_at)
        self.exp = self._get_expiration(expiration_seconds)
        self.other_claims = kwargs
        self.assertion_validator = assertion_validator or AssertionValidator

    @staticmethod
    def _get_expiration(expiration_seconds):
        return time.time() + expiration_seconds

    @staticmethod
    def _get_issued_at(include_issued_at):
        iat = None
        if include_issued_at:
            iat = time.time()
        return iat

    @staticmethod
    def _serialize_private_key(private_key, password=None):
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
                    error = err.message
        if error:
            raise errors.InvalidPrivateKeyError(error)
        else:
            return pvt_key

    @property
    def token_request_string(self):
        grant_type = "grant_type={}".format(self._grant_type)
        assertion = "&assertion={}".format(self.create_token_assertion())
        scope = "&scope={}".format(self.scope) if self.scope else ""
        client_id = "&client_id={}".format(self.client_id) if self.client_id else ""
        return "{}{}{}{}".format(grant_type, assertion, scope, client_id)

    @property
    def claims_payload(self):
        payload = {
            'iss': self.iss,
            'aud': self.aud,
            'sub': self.sub,
            'exp': self.exp
        }
        optional_claims = {}
        for claim in self._non_required_claims:
            val = getattr(self, claim)
            if val:
                optional_claims[claim] = val
        payload.update(**optional_claims)
        payload.update(**self.other_claims)
        return payload

    def create_token_assertion(self):
        self.validate_token_claims(self.claims_payload)

        return jwt.encode(
            self.claims_payload, self.signature, self._crypto_algorithm
        ).decode('utf-8')

    def validate_token_claims(self, claims):

        if not self.assertion_validator.validate_required(
                claims, self._required_claims
        ):
            log.debug('Missing required claims. %s', claims)
            raise errors.MissingRequiredClaimError(
                description='One or more required claims contained null value',
            )

        if not self.assertion_validator.validate_iss(self.iss):
            log.debug('Invalid issuer (iss) value. %s', self.iss)
            raise errors.InvalidJWTClaimError(
                description='Issuer (iss) claim contains an invalid value',
            )

        if not self.assertion_validator.validate_sub(self.sub):
            log.debug('Invalid subject (sub) value. %s', self.sub)
            raise errors.InvalidJWTClaimError(
                description='Subject (sub) claim contains an invalid value',
            )

        if not self.assertion_validator.validate_aud(self.aud):
            log.debug('Invalid audience (aud) value. %s', self.aud)
            raise errors.InvalidJWTClaimError(
                description='Audience (aud) claim contains an invalid value',
            )

        if not self.assertion_validator.validate_nbf(self.nbf, self.exp):
            log.debug('Invalid not_before (nbf) value. %s', self.nbf)
            raise errors.InvalidJWTClaimError(
                description='Not Before (nbf) claim contains an invalid value',
            )

        if not self.assertion_validator.validate_jti(self.jti):
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

        if not self.assertion_validator.validate_additional_claims(
                self.other_claims
        ):
            log.debug(
                'One or more additional claims contain invalid values. %s',
                self.other_claims
            )
            raise errors.InvalidJWTClaimError(
                description='Additional claims contain invalid values',
            )
