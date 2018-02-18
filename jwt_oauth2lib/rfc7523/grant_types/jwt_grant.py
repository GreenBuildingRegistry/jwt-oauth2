#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
import json
import logging

# Imports from Third Party Modules
import jwt
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types.base import GrantTypeBase

# Local Imports
from jwt_oauth2lib.rfc7523.request_validator import RequestValidator

# Constants
log = logging.getLogger(__name__)  # pylint: disable-msg=invalid-name
INVALID_CLAIM = "Invalid Token Claim: {msg}. {payload}"
INVALID_TOKEN = "Invalid Token: {msg}. {payload}"


class JWTGrant(GrantTypeBase):
    """JWT grant

    JSON Web Token grant: https://tools.ietf.org/html/rfc7523
    """
    # pylint: disable-msg=abstract-method

    def __init__(self, request_validator=None, **kwargs):
        self.request_validator = request_validator or RequestValidator()
        super(JWTGrant, self).__init__(request_validator, **kwargs)

    def create_token_response(self, request, token_handler):
        """Create a new access token from a jwt request.

        If valid and authorized, the authorization server issues an access
        token as described in RFC6749 `Section 5.1`_. If the request failed
        verification or is invalid, the authorization server returns an error
        response as described in RFC6749 `Section 5.2`_.

        .. _`Section 5.1`: http://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
        """
        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
        try:
            log.debug('Validating JSON web token request, %s.', request)
            self.validate_token_request(request)
        except errors.OAuth2Error as err:
            return headers, err.json, err.status_code

        token = token_handler.create_token(
            request,
            refresh_token=False,
            save_token=False
        )

        for modifier in self._token_modifiers:
            token = modifier(token)  # pragma: no cover
        self.request_validator.save_token(token, request)

        log.debug(
            'Issuing new token to client id %s (%s), %s.',
            request.client_id, request.client, token
        )
        return headers, json.dumps(token), 200

    def validate_token_request(self, request):
        """validate token request by request attributes and jwt claims."""
        # pylint: disable-msg=too-many-branches

        # REQUIRED. Per http://tools.ietf.org/html/rfc7523#section-2.1, value
        # MUST be set to "urn:ietf:params:oauth:grant-type:jwt-bearer".
        # Note: support for receiving client authentication jwt requests
        # following the parameter values specified by rfc7523 section 2.2 is
        # not yet implemented https://tools.ietf.org/html/rfc7523#section-2.2
        if request.grant_type != 'urn:ietf:params:oauth:grant-type:jwt-bearer':
            raise errors.UnsupportedGrantTypeError(request=request)

        for validator in self.custom_validators.pre_token:
            validator(request)

        if getattr(request, 'assertion', None) is None:
            raise errors.InvalidRequestError(
                description='Missing jwt assertion parameter.',
                request=request
            )
        elif len(request.assertion.split(',')) > 1:
            raise errors.InvalidRequestError(
                description='Assertion MUST NOT contain more than one JWT',
                request=request
            )

        # Jwt MUST contain exp claim per
        # https://tools.ietf.org/html/rfc7523#section-3. Signature verification
        # is postponed for handling in request_validator after retrieval of
        # public key matching correct client.
        options = {
            'verify_signature': False,
            'require_exp': True
        }

        # The JWT MUST contain an "aud" (audience) claim containing a
        # value that identifies the authorization server as an intended
        # audience.
        audience = self.request_validator.get_audience(request)
        try:
            payload = jwt.decode(
                request.assertion, '', audience=audience, options=options,
                algorithms=['RS256']
            )
        except jwt.ExpiredSignatureError:
            raise errors.InvalidGrantError(
                description='JWT request contains an expired signature',
                request=request
            )
        except jwt.ImmatureSignatureError:
            raise errors.InvalidGrantError(
                description='JWT is not yet valid (nbf)',
                request=request
            )
        except jwt.InvalidAudienceError:
            raise errors.InvalidGrantError(
                description='JWT request contains invalid audience claim',
                request=request
            )
        except jwt.MissingRequiredClaimError:
            raise errors.InvalidGrantError(
                description='JWT is missing a required claim',
                request=request
            )
        except jwt.DecodeError:
            raise errors.InvalidGrantError(
                description='One of more errors occurred during JWT decode',
                request=request
            )

        # The JWT MUST contain an "iss" (issuer) claim that contains a
        # unique identifier for the entity that issued the JWT.  In the
        # absence of an application profile specifying otherwise,
        # compliant applications MUST compare issuer values using the
        # Simple String Comparison method defined in Section 6.2.1 of RFC
        # 3986 [RFC3986] https://tools.ietf.org/html/rfc7523#section-3
        if not self.request_validator.validate_issuer(request, payload):
            msg = 'Missing or invalid (iss) claim'
            log_msg = INVALID_CLAIM.format(msg=msg, payload=payload)
            log.debug(log_msg)
            raise errors.InvalidGrantError(
                description=msg,
                request=request
            )

        # If client_id is not supplied as a param or claim, the issuer must be
        # client_id. client_id is validated, rather than authenticated, since
        # authentication is completed by validating token signature.
        # request.client is set in validate_client_id.
        if not request.client_id:
            request.client_id = payload.get('client_id', payload.get('iss'))
        if not self.request_validator.validate_client_id(
                request.client_id, request
        ):
            log.debug('Client authentication failed, %s.', request)
            raise errors.InvalidClientError(request=request)

        # A validate_signature method that provides functionality for
        # retrieving the public key appropriate to the issuer or client_id,
        # and completes the decoding of the jwt using said key,
        # MUST be added to the request_validator class.
        if not self.request_validator.validate_signature(
                request, request.client, request.assertion
        ):
            msg = 'Missing or invalid token signature'
            log_msg = INVALID_TOKEN.format(msg=msg, payload=payload)
            log.debug(log_msg)
            raise errors.InvalidGrantError(
                description=msg,
                request=request
            )

        # Ensure client is authorized use of this grant type.
        self.validate_grant_type(request)

        # The request_validator class must include a validate_subject method
        # that ensures the user ('sub') exists and is active.
        if not self.request_validator.validate_subject(
                request, request.client, payload
        ):
            msg = 'Missing or invalid (sub) claim'
            log_msg = INVALID_CLAIM.format(msg=msg, payload=payload)
            log.debug(log_msg)
            raise errors.InvalidGrantError(
                description=msg,
                request=request
            )

        # Since a jwt flow acts much like a refresh token flow, giving the
        # client access to the user's resources without the user present,
        # server's MAY wish to validate an existing authorization exists
        # containing explicit offline_access via scope or implied via
        # refresh token. A validate_offline_access method MUST be added to your
        # request_validator class; it is recommended that
        # request.refresh_tokens be set to avoid another query to validate
        # other scopes against previously authorized scopes.
        log.debug(
            'Validating offline access for client %s.', request.client
        )
        if not self.request_validator.validate_offline_access(
                request, request.user, request.client
        ):
            msg = 'Client not authorized for offline_access grants'
            log_msg = INVALID_CLAIM.format(msg=msg, payload=payload)
            log.debug(log_msg)
            raise errors.InvalidGrantError(
                description=msg,
                request=request
            )

        # A validate_refresh_scopes method must be implemented in the
        # request_validator class, to either verify that all requested scopes
        # are within previously authorized scopes, or allow all scopes that
        # are available to the client.
        requested_scope = request.scope or payload.get('scope')
        if not self.request_validator.validate_refresh_scopes(
                request, getattr(request, 'refresh_tokens', None),
                requested_scope
        ):
            log.debug(
                'Client %s lacks requested scopes, %s.',
                request.client_id, request.scopes
            )
            raise errors.InvalidScopeError(request=request)

        # A jwt MAY contain additional claims. A validate_additional_claims
        # method should be implemented in the request_validator class to
        # validate all other jwt claims.
        if not self.request_validator.validate_additional_claims(
                request, payload
        ):
            msg = (
                "One or more additional claims failed validation. See "
                "provider for jwt claim requirements"
            )
            raise errors.InvalidGrantError(
                description=msg,
                request=request
            )

        for validator in self.custom_validators.post_token:
            validator(request)
