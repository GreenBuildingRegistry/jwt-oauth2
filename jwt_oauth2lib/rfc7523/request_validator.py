#!/usr/bin/env python
# encoding: utf-8
"""
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Third Party Modules
from oauthlib.oauth2 import RequestValidator as LibRequestValidator


class RequestValidator(LibRequestValidator):
    # pylint: disable-msg=abstract-method
    algorithms = ['RS256']

    def get_audience(self, request, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_issuer(self, request, token, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_signature(self, request, client, token, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_subject(self, request, client, payload, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_offline_access(self, request, user, client, by_scope=False,
                                *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_refresh_scopes(self, request, prior_tokens, requested_scope,
                                *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_additional_claims(self, request, payload, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')
