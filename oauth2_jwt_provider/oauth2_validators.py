#!/usr/bin/env python
# encoding: utf-8
"""
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
import logging

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
    OAuth2Validator as RequestValidator,
    GRANT_TYPE_MAPPING
)
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

log = logging.getLogger('oauth2_provider')
User = get_user_model()


class OAuth2Validator(RequestValidator):
    # pylint: disable-msg=abstract-method
    algorithms = ['RS256']

    def get_audience(self):
        return jwt_oauth2_settings.JWT_AUDIENCE

    def validate_issuer(self, token):
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
        if not getattr(client, 'public_key', None):
            log.debug("Failed basic auth: no public key "
                      "registered to client {}".format(request.client_id))
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

    def validate_subject(self, request, client, payload):
        sub = payload.get('sub')
        if not sub:
            return False
        else:
            if client.authorization_grant_type == GRANT_CLIENT_CREDENTIALS:
                if client.client_id != sub:
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

    def validate_additional_claims(self):
        return True
