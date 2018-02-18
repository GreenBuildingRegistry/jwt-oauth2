#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Third Party Modules
from oauthlib.oauth2 import (
    AuthorizationEndpoint,
    BearerToken,
    ResourceEndpoint,
    RevocationEndpoint,
    TokenEndpoint,
)
from oauthlib.oauth2.rfc6749.grant_types import (
    AuthCodeGrantDispatcher,
    AuthorizationCodeGrant,
    ClientCredentialsGrant,
    ImplicitGrant,
    OpenIDConnectAuthCode,
    OpenIDConnectImplicit,
    RefreshTokenGrant,
    ResourceOwnerPasswordCredentialsGrant,
)

# Local Imports
from jwt_oauth2lib.rfc7523.grant_types import JWTGrant


class Server(AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint,
             RevocationEndpoint):
    """An all-in-one endpoint featuring all four major grant types, and jwt."""

    def __init__(self, request_validator, token_expires_in=None,
                 token_generator=None, refresh_token_generator=None,
                 *args, **kwargs):
        # pylint: disable-msg=too-many-locals
        # pylint: disable-msg=unused-argument
        """Construct a new all-grants-in-one server.

        :param request_validator: An implementation of
                                  oauthlib.oauth2.RequestValidator.
        :param token_expires_in: An int or a function to generate a token
                                 expiration offset (in seconds) given a
                                 oauthlib.common.Request object.
        :param token_generator: A function to generate a token from a request.
        :param refresh_token_generator: A function to generate a token from a
                                        request for the refresh token.
        :param kwargs: Extra parameters to pass to authorization-,
                       token-, resource-, and revocation-endpoint constructors.
        """
        auth_grant = AuthorizationCodeGrant(request_validator)
        implicit_grant = ImplicitGrant(request_validator)
        password_grant = ResourceOwnerPasswordCredentialsGrant(
            request_validator)
        credentials_grant = ClientCredentialsGrant(request_validator)
        refresh_grant = RefreshTokenGrant(request_validator)
        openid_connect_auth = OpenIDConnectAuthCode(request_validator)
        openid_connect_implicit = OpenIDConnectImplicit(request_validator)
        jwt_grant = JWTGrant(request_validator)

        bearer = BearerToken(
            request_validator, token_generator,
            token_expires_in, refresh_token_generator
        )

        auth_grant_choice = AuthCodeGrantDispatcher(
            default_auth_grant=auth_grant,
            oidc_auth_grant=openid_connect_auth
        )

        # See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations  # noqa
        # for valid combinations see also oauthlib.oauth2 AuthorizationEndpoint
        AuthorizationEndpoint.__init__(
            self, default_response_type='code',
            response_types={
                'code': auth_grant_choice,
                'token': implicit_grant,
                'id_token': openid_connect_implicit,
                'id_token token': openid_connect_implicit,
                'code token': openid_connect_auth,
                'code id_token': openid_connect_auth,
                'code token id_token': openid_connect_auth,
                'none': auth_grant
            },
            default_token_type=bearer
        )
        TokenEndpoint.__init__(
            self, default_grant_type='authorization_code',
            grant_types={
                'authorization_code': auth_grant,
                'password': password_grant,
                'client_credentials': credentials_grant,
                'refresh_token': refresh_grant,
                'openid': openid_connect_auth,
                'urn:ietf:params:oauth:grant-type:jwt-bearer': jwt_grant
            },
            default_token_type=bearer)
        ResourceEndpoint.__init__(
            self, default_token='Bearer',
            token_types={'Bearer': bearer}
        )
        RevocationEndpoint.__init__(self, request_validator)
