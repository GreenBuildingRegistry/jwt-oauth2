#!/usr/bin/env python
# encoding: utf-8
"""
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
