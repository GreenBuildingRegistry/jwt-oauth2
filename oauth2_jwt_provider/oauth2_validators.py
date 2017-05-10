#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
import logging
import time

# Imports from Django
from django.contrib.auth import get_user_model
from django.core.exceptions import (
    ImproperlyConfigured,
    MultipleObjectsReturned,
    ObjectDoesNotExist,
)

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
        if not token.get('iss'):
            return False
        else:
            iss_model = jwt_oauth2_settings.ISSUER_IDENTIFIER_MODEL
            iss_attr = jwt_oauth2_settings.ISSUER_IDENTIFIER_ATTR
            qsfilter = {iss_attr: token['iss']}
            try:
                iss_model.objects.get(**qsfilter)
            except ObjectDoesNotExist:
                return False
            except MultipleObjectsReturned:
                raise ImproperlyConfigured(
                    "Issuer identifier settings MUST create a unique "
                    "identifier. Model {} with attr {} returned multiple "
                    "results".format(iss_model, iss_attr)
                )
            else:
                return True

    def validate_signature(self, request, client, token):
        """
        Ensure jwt contains a valid digital signature as decoded using
        public_key associated with client and RS256 algorithm.
        """
        if not getattr(client, 'public_key', None):
            log.debug("Failed basic auth: no public key "
                      "registered to client %s", request.client_id)
            return False
        try:
            options = {'verify_signature': True, 'verify_aud': False}
            verified_payload = jwt.decode(
                token,
                client.public_key.key,
                options=options,
                issuer=request.client_id,
                algorithms=self.algorithms
            )
        except jwt.InvalidTokenError:
            return False
        else:
            assert verified_payload
            return True

    def validate_subject(self, request, client, token):
        """
        Ensure an 'sub' claim exists and refers to a valid, active user or is
        client's client_id, if client uses client_credentials grant type.
        """
        sub = token.get('sub')
        if not sub:
            return False
        else:
            if client.authorization_grant_type == GRANT_CLIENT_CREDENTIALS:
                if sub != client.client_id:
                    return False
                else:
                    user = client.user
            else:
                try:
                    user = User.objects.get(username=sub)
                except User.DoesNotExist:
                    return False
            if not user.is_active:
                return False
            else:
                request.user = user
                return True

    def validate_offline_access(self, request, user, client, by_scope=False):
        """Ensure client is authorized for offline access to resources."""
        if client.authorization_grant_type == GRANT_CLIENT_CREDENTIALS:
            return True
        elif by_scope:
            available_scopes = get_scopes_backend().get_available_scopes(
                application=client, request=request
            )
            return any('offline' in scope for scope in available_scopes)
        else:
            refresh_tokens = RefreshToken.objects.filter(
                user=user, application=client
            )
            if not refresh_tokens:
                return False
            else:
                request.refresh_tokens = refresh_tokens
                request.original_scopes = set(
                    scope for token in refresh_tokens
                    for scope in utils.scope_to_list(token.access_token.scope)
                )
                return True

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

        # are the requested scopes within the client's available scopes
        if not self.validate_scopes(
                request.client_id, request.scopes, request.client, request
        ):
            return False
        # are the requested scopes in the client's previously authorized scopes
        elif not set(request.scopes).issubset(set(original_scopes)):
            return False
        else:
            return True

    def validate_additional_claims(self, request, token):
        """Ensure token claims pass all additional validations."""
        # pylint: disable-msg=unused-argument
        validations = []
        validations.append(self._validate_max_exp(token['exp']))
        if not all(valid for valid in validations):
            return False
        else:
            return True

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
            return exp - timestamp_now < max_sec
        else:
            return True
