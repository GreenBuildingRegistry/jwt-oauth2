#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
import logging
import time

# Imports from Django
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured

# Imports from Third Party Modules
import jwt
from oauth2_provider.models import AbstractApplication, RefreshToken
from oauth2_provider.oauth2_validators import (
    OAuth2Validator as RequestValidator
)
from oauth2_provider.oauth2_validators import GRANT_TYPE_MAPPING
from oauth2_provider.scopes import get_scopes_backend
from oauthlib.oauth2.rfc6749 import utils

# Local Imports
from oauth2_jwt_provider.settings import jwt_oauth2_settings

GRANT_CLIENT_CREDENTIALS = AbstractApplication.GRANT_CLIENT_CREDENTIALS

GRANT_TYPE_MAPPING['urn:ietf:params:oauth:grant-type:jwt-bearer'] = (
    AbstractApplication.GRANT_AUTHORIZATION_CODE,
    AbstractApplication.GRANT_PASSWORD,
    AbstractApplication.GRANT_CLIENT_CREDENTIALS
)
BY_SCOPE = getattr(jwt_oauth2_settings, 'ALLOW_TRUSTED_BY_SCOPE', False)
TRUSTED_APP_GROUP = getattr(jwt_oauth2_settings, 'TRUSTED_OAUTH_GROUP', None)

log = logging.getLogger('oauth2_provider')  # pylint: disable-msg=invalid-name
User = get_user_model()  # pylint: disable-msg=invalid-name


class OAuth2Validator(RequestValidator):
    """Extension of oauth2_provider.oauth2_validators.OAuth2Validator to
     include validation methods required by JWTGrant."""
    # pylint: disable-msg=abstract-method
    algorithms = ['RS256']

    def get_audience(self, request):
        """Retrieve authorization server identifier (audience) from settings"""
        # pylint: disable-msg=unused-argument
        return jwt_oauth2_settings.JWT_AUDIENCE

    def validate_issuer(self, request, token):
        """
        Ensure an 'iss' claim exists and refers to a valid, unique issuer as
        specified by settings ISSUER_IDENTIFIER_MODEL, ISSUER_IDENTIFIER_ATTR
        """
        # pylint: disable-msg=unused-argument
        # if the 'iss' claim is not present in the token the token is invalid
        if not token.get('iss'):
            valid_iss_claim = False
        else:
            # if there is an 'iss' claim, use model and attribute defined in
            # settings to ensure claim resolves to one, and only one, issuer.
            iss_model = jwt_oauth2_settings.ISSUER_IDENTIFIER_MODEL
            iss_attr = jwt_oauth2_settings.ISSUER_IDENTIFIER_ATTR
            qsfilter = {iss_attr: token['iss']}
            try:
                iss_model.objects.get(**qsfilter)
                valid_iss_claim = True
            except iss_model.DoesNotExist:
                valid_iss_claim = False
            except iss_model.MultipleObjectsReturned:
                raise ImproperlyConfigured(
                    "Issuer identifier settings MUST create a unique "
                    "identifier. Model {} with attr {} returned multiple "
                    "results".format(iss_model, iss_attr)
                )
        return valid_iss_claim

    def validate_signature(self, request, client, token):
        """
        Ensure jwt contains a valid digital signature as decoded using
        public_key associated with client and RS256 algorithm.
        """
        if not getattr(client, 'public_key', None):
            log.debug("Failed basic auth: no public key "
                      "registered to client %s", request.client_id)
            valid_token_signature = False
        else:
            try:
                options = {'verify_signature': True, 'verify_aud': False}
                jwt.decode(
                    token,
                    client.public_key.key,
                    options=options,
                    issuer=request.client_id,
                    algorithms=self.algorithms
                )
                valid_token_signature = True
            except jwt.InvalidTokenError:
                valid_token_signature = False
        return valid_token_signature

    def validate_subject(self, request, client, token):
        """
        Ensure an 'sub' claim exists and refers to a valid, active user or is
        client's client_id, if client uses client_credentials grant type.
        """
        user = None
        sub = token.get('sub')
        # if 'sub' claim is not present or is null, the token is invalid.
        if not sub:
            valid_sub_claim = False
        else:
            # for client credentials grant types, 'sub' MUST equal client_id
            # https://tools.ietf.org/html/rfc7523#section-3
            if client.authorization_grant_type == GRANT_CLIENT_CREDENTIALS:
                if sub == client.client_id:
                    user = client.user
            else:
                try:
                    user = User.objects.get(username=sub)
                except User.DoesNotExist:
                    pass

            # user must exist and be active, whether user is subject or client
            if user and user.is_active:
                request.user = user
                valid_sub_claim = True
            else:
                valid_sub_claim = False
        return valid_sub_claim

    def validate_offline_access(self, request, user, client,
                                by_scope=BY_SCOPE):
        """Ensure client is authorized for offline access to resources.

        Client credentials grant type applications are automatically authorized
        for offline access since the client is the resource owner.

        For all other grant types:
            The existence of refresh tokens granted to the client for the
            resource owner creates an implicit offline access authorization.

            Trusted clients can be granted explicit offline access by_scope
            and either setting the client's 'skip_authorization' attribute
            to True or adding the client app owner to the TRUSTED_APP_GROUP.
        """
        if client.authorization_grant_type == GRANT_CLIENT_CREDENTIALS:
            valid_offline_auth = True
        else:
            refresh_tokens = RefreshToken.objects.filter(
                user=user, application=client
            )
            if refresh_tokens:
                request.refresh_tokens = refresh_tokens
                request.original_scopes = set(
                    scope for token in refresh_tokens
                    for scope in utils.scope_to_list(token.access_token.scope)
                )
                valid_offline_auth = True
            elif by_scope:
                client_user_groups = client.user.groups.values_list(
                    "name", flat=True
                )
                skip_auth = getattr(client, 'skip_authorization', False)
                available_scopes = get_scopes_backend().get_available_scopes(
                    application=client, request=request
                )
                if TRUSTED_APP_GROUP in client_user_groups or skip_auth:
                    valid_offline_auth = any(
                        'offline' in scope for scope in available_scopes
                    )
                else:
                    valid_offline_auth = False
            else:
                valid_offline_auth = False
        return valid_offline_auth

    def validate_refresh_scopes(self, request, prior_tokens, requested_scope):
        """
        Ensure requested scopes are in client's prior authorized scopes or
        within the limits of client's default scopes
        """
        if prior_tokens:
            original_scopes = set(
                scope for token in prior_tokens
                for scope in utils.scope_to_list(token.access_token.scope)
            )
        else:
            original_scopes = self.get_default_scopes(
                request.client_id, request
            )

        if requested_scope:
            request.scopes = utils.scope_to_list(requested_scope)
        else:
            request.scopes = original_scopes

        # scope request is invalid if not within the client's available scopes
        if not self.validate_scopes(
                request.client_id, request.scopes, request.client, request
        ):
            valid_scope_request = False
        # scope request is invalid if not in the client's previously
        # authorized scopes
        elif not set(request.scopes).issubset(set(original_scopes)):
            valid_scope_request = False
        else:
            valid_scope_request = True
        return valid_scope_request

    def validate_additional_claims(self, request, token):
        """Ensure token claims pass all additional validations."""
        # pylint: disable-msg=unused-argument
        validations = []
        validations.append(self._validate_max_exp(token['exp']))
        if not all(valid for valid in validations):
            valid_additional_claims = False
        else:
            valid_additional_claims = True
        return valid_additional_claims

    def _validate_max_exp(self, exp):
        """
        Ensure expiration date is within the maximum allowable window
        as defined by settings.
        (rfc7523 section 3: The authorization server may reject JWTs with an
         "exp" claim value that is unreasonably far in the future.)
        """
        max_exp = jwt_oauth2_settings.JWT_MAX_EXPIRE_SECONDS or 0
        skew = jwt_oauth2_settings.TIME_SKEW_ALLOWANCE_SECONDS or 0
        max_sec = max_exp + skew
        if max_sec and max_sec > 0:
            exp = float(exp)
            timestamp_now = time.time()
            valid_exp_length = exp - timestamp_now < max_sec
        else:
            valid_exp_length = True
        return valid_exp_length
