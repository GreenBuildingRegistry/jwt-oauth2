#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals
import time


class AssertionValidator(object):

    def validate_required(self, claims, required, *args, **kwargs):
        """Ensure all required claims have a non-null value.

        :param claims: claims payload dict
        :param required: list of required claim keys

        Method is used by:
            - JWT Grant Request client
        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        return all(claims.get(claim) for claim in required)

    def validate_iss(self, iss, *args, **kwargs):
        """Ensure 'iss' claim meets provider issuer identification rules.

        :param iss: token issuer

        Method is used by:
            - JWT Grant Request client
        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_aud(self, aud, *args, **kwargs):
        """Ensure 'aud' claim meets provider audience identification rules.

        :param aud: token audience

        Method is used by:
            - JWT Grant Request client
        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_sub(self, sub, *args, **kwargs):
        """Ensure 'sub' claim identifies provider recognized resource owner.

        :param sub: token subject (resource owner)

        Method is used by:
            - JWT Grant Request client
        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_nbf(self, nbf, exp, *args, **kwargs):
        """
        Ensure 'nbf' claim represents a valid timestamp before which the token
        MUST NOT be accepted.

        Valid 'nbf' should be a timestamp that is less than the token
        expiration while the 'exp' value is greater than the current time.

        :param nbf: not before value
        :param exp: token expiration timestamp

        Method is used by:
            - JWT Grant Request client
        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        valid_nbf = True
        if nbf:
            valid_nbf = (nbf < exp and exp > time.time())
        return valid_nbf

    def validate_jti(self, jti, *args, **kwargs):
        """Ensure 'jti' claim is a unique token identifier.

        :param jti: token jti

        Method is used by:
            - JWT Grant Request client
        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_scope(self, scope, *args, **kwargs):
        """Ensure 'scope' parameter is within provider allowed scopes.

        :param scope: requested access scope

        Method is used by:
            - JWT Grant Request client
        .. _`Section 2.1`: https://tools.ietf.org/html/rfc7523#section-2.1
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_client_id(self, client_id, *args, **kwargs):
        """Ensure 'client_id' claim meets provider requirements.

        :param client_id: client_id

        Method is used by:
            - JWT Grant Request client
        .. _`Section 2.1`: https://tools.ietf.org/html/rfc7523#section-2.1
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_additional_claims(self, claims, *args, **kwargs):
        """Ensure additional claims meet provider requirements.

        :param claims: token claims

        Method is used by:
            - JWT Grant Request client
        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        raise NotImplementedError('Subclasses must implement this method.')
