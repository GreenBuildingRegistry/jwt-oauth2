#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals


class AssertionValidator(object):

    def validate_required(self, claims, required, *args, **kwargs):
        return all(claims.get(claim) for claim in required)

    def validate_iss(self, iss, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_aud(self, aud, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_sub(self, sub, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_nbf(self, nbf, exp, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_jti(self, jti, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_scope(self, scope, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_client_id(self, scope, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_additional_claims(self, claims, *args, **kwargs):
        raise NotImplementedError('Subclasses must implement this method.')
