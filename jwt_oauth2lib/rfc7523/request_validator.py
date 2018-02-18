#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Third Party Modules
from oauthlib.oauth2 import RequestValidator as LibRequestValidator


class RequestValidator(LibRequestValidator):
    """Extension of oauthlib.oauth2.RequestValidator to include validation
    methods required by JWTGrant."""
    # pylint: disable-msg=abstract-method
    algorithms = ['RS256']

    def get_audience(self, request, *args, **kwargs):
        """Return a value that identifies the authorization server.

        According to rfc7523, The JWT MUST contain an "aud" (audience) claim
        containing a value that identifies the authorization server as an
        intended audience.
            - The token endpoint URL of the authorization server MAY be used
              as a value for an "aud" element to identify the authorization
              server as an intended audience of the JWT.

        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: Authorization server identifier

        Method is used by:
            - JWT Grant

        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_issuer(self, request, token, *args, **kwargs):
        """Ensure jwt contains 'iss' claim uniquely identifying issuing client.

        :param request: The HTTP Request (oauthlib.common.Request)
        :param token:  JSON Web Token payload
        :rtype: True or False

        Method is used by:
            - JWT Grant

        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_signature(self, request, client, token, *args, **kwargs):
        """Ensure jwt digital signature is valid.

        According to rfc7523, the JWT MUST be digitally signed or have a
        Message Authentication Code (MAC) applied by the issuer, and invalid
        signatures or MACs MUST be rejected.

        The "RS256" algorithm, from [JWA], is a mandatory-to-implement JSON
        Web Signature algorithm

        :param request: The HTTP Request (oauthlib.common.Request)
        :param client: Client object set by you, see authenticate_client.
        :param token:  JSON Web Token payload
        :rtype: True or False

        Method is used by:
            - JWT Grant

        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        .. _`Section 5`: https://tools.ietf.org/html/rfc7523#section-5
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_subject(self, request, client, token, *args, **kwargs):
        """Ensure jwt contains 'sub' claim identifying the subject of the jwt.

        The request.user attribute should be set to the resource owner
        identified by the subject claim.

        According to rfc7523, there are two cases for subject identification.
            - Authorization grant, the subject is typically an authorized
              accessor (ie resource owner), but may be an identifier denoting
              anonymous user.
            - Client authentication, the subject MUST be the client's client_id

        :param request: The HTTP Request (oauthlib.common.Request)
        :param client: Client object set by you, see authenticate_client.
        :param token:  JSON Web Token payload
        :rtype: True or False

        Method is used by:
            - JWT Grant

        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_offline_access(self, request, user, client, by_scope=False,
                                *args, **kwargs):
        """Ensure client is authorized for offline access.

        Since a jwt flow acts much like a refresh token flow, giving the
        client access to the user's resources without the user present,
        server's MAY wish to validate an existing authorization exists
        containing explicit offline_access via scope or implied via
        refresh token.

        :param request: The HTTP Request (oauthlib.common.Request)
        :param user: Resource owner
        :param client: Client object set by you, see authenticate_client.
        :param by_scope: True or False to flag chosen method of validation.
        :rtype: True or False

        Method is used by:
            - JWT Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_refresh_scopes(self, request, prior_tokens, requested_scope,
                                *args, **kwargs):
        """Validate requested scopes against prior authorizations.

        Since the jwt flow permits access to user resources without user being
        present, newly requested scope should be within any previously
        authorized scopes, or limited to the list of scopes that are available
        to the client.

        :param request: The HTTP Request (oauthlib.common.Request)
        :param prior_tokens: Tokens previously granted to the client on behalf
            of the resource owner.
        :param requested_scope: list of requested scopes
        :rtype: True or False

        Method is used by:
            - JWT Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_additional_claims(self, request, token, *args, **kwargs):
        # pylint: disable-msg=no-self-use
        # pylint: disable-msg=unused-argument
        """Ensure any additional claims meet authentication server requirements

        According to rfc7523, the JWT may contain additional claims including,
        but not limited to:
            - Issued at (iat): authorization server may reject JWTs with an
             "iat" claim value that is unreasonably far in the past
            - JWT ID (jti), unique token identifier: The authorization server
              MAY ensure that JWTs are not replayed by maintaining the set of
              used "jti" values

            note: While not before (nbf) is another known, optional claim, it
             is already validated by the jwt.decode method.

        :param request: The HTTP Request (oauthlib.common.Request)
        :param token:  JSON Web Token payload
        :rtype: True or False

        Method is used by:
            - JWT Grant

        .. _`Section 3`: https://tools.ietf.org/html/rfc7523#section-3
        """
        return True
