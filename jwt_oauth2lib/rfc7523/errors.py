#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals


class InvalidJWTClaimError(Exception):
    """The JWT contains a missing or invalid claim value."""
    error = 'invalid_claim'
    description = ''

    def __init__(self, description=None):  # pragma: no cover
        self.description = description or self.description
        message = '({}) {}'.format(self.error, self.description)
        super(InvalidJWTClaimError, self).__init__(message)


class InvalidPrivateKeyError(InvalidJWTClaimError):
    """The private key supplied for jwt digital signature is invalid or
    not a supported type."""
    error = 'invalid_private_key'


class MissingRequiredClaimError(InvalidJWTClaimError):
    """A required jwt claim is missing or has an invalid value."""
    error = 'missing_required_claim'


class InvalidRequestParameterError(InvalidJWTClaimError):
    """An request parameter has been supplied with an invalid value."""
    error = 'invalid_param'
