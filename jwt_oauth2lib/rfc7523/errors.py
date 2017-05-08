#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Third Party Modules
from oauthlib.oauth2.rfc6749.errors import OAuth2Error


class InvalidJWTClaimError(OAuth2Error):
    error = 'invalid_claim'
    status_code = 401


class InvalidJWTError(OAuth2Error):
    error = 'invalid_JSON_web_token'
    status_code = 401


class InvalidJWTSignatureError(OAuth2Error):
    error = 'invalid_JWT_signature'
    status_code = 401


class JWTClientError(Exception):
    error = None
    description = ''

    def __init__(self, description=None):
        self.description = description or self.description
        message = '({}) {}'.format(self.error, self.description)
        super(JWTClientError, self).__init__(message)


class InvalidPrivateKey(JWTClientError):
    error = 'invalid_private_key'


class MissingRequiredClaim(JWTClientError):
    error = 'missing_required_claim'


class InvalidClaimValue(JWTClientError):
    error = 'invalid_claim'


class InvalidRequestParameter(JWTClientError):
    error = 'invalid_param'
