#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>

This module is largely derived from Django OAuth Toolkit and DRF settings.

Settings for the OAuth2 JWT Provider are all namespaced in the
OAUTH2_JWT_PROVIDER setting.

For example your project's `settings.py` file might look like this:

OAUTH2_JWT_PROVIDER = {
    'JWT_AUDIENCE': 'https://site.address/oauth/token/'
    'PUBLIC_KEY_MODEL'': 'oauth2_jwt_provider.PublicKey',
    'PUBLIC_KEY_EXPIRE_DAYS': 90
}

This module provides the `jwt_oauth2_settings` object, that is used to access
OAuth2 JWT Provider settings, checking for user settings first, then
OAuth2 Provider user settings for a limited set of attributes, then falling
back to the defaults.
"""
from __future__ import unicode_literals

# Imports from Standard Library
import importlib

# Imports from Django
from django.apps import apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# Imports from Third Party Modules
from oauth2_provider.settings import oauth2_settings

USER_SETTINGS = getattr(settings, 'OAUTH2_JWT_PROVIDER', {})
DOT_USER_SETTINGS = getattr(settings, 'OAUTH2_PROVIDER', {})

DEFAULTS = {
    'JWT_AUDIENCE': None,
    'JWT_MAX_EXPIRE_SECONDS': 300,
    'TIME_SKEW_ALLOWANCE_SECONDS': 30,
    'PUBLIC_KEY_MODEL': 'oauth2_jwt_provider.PublicKey',
    'PUBLIC_KEY_EXPIRE_DAYS': None,
    'ISSUER_IDENTIFIER_MODEL': oauth2_settings.APPLICATION_MODEL,
    'ISSUER_IDENTIFIER_ATTR': 'client_id',
    'OFFLINE_SCOPE': 'offline',
    'SCOPES': {
        "read": "Reading scope",
        "write": "Writing scope",
        "offline": "Offline Access scope"
    },
    'OAUTH2_SERVER_CLASS': 'jwt_oauth2lib.Server',
    'OAUTH2_VALIDATOR_CLASS':
        'oauth2_jwt_provider.oauth2_validators.OAuth2Validator',
    'DEVELOPER_GROUP': None,
    'TRUSTED_OAUTH_GROUP': None,
    'ALLOW_SUPERUSERS': False,
    'ALLOW_TRUSTED_BY_SCOPE': True
}

# List of settings that cannot be empty
MANDATORY = (
    'JWT_AUDIENCE',
    'PUBLIC_KEY_MODEL',
    'OAUTH2_SERVER_CLASS',
    'OAUTH2_VALIDATOR_CLASS',
    'ISSUER_IDENTIFIER_MODEL',
    'ISSUER_IDENTIFIER_ATTR',
)

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'PUBLIC_KEY_MODEL',
    'ISSUER_IDENTIFIER_MODEL',
    'OAUTH2_SERVER_CLASS',
    'OAUTH2_VALIDATOR_CLASS',
)

# List of settings that may be set in OAUTH2_JWT_PROVIDER or OAUTH2_PROVIDER
DOT_SETTING_ATTRS = {
    'OAUTH2_SERVER_CLASS',
    'OAUTH2_VALIDATOR_CLASS',
    'SCOPES'
}


def perform_import(val, setting_name):
    """
    If the given setting is a string import notation,
    then perform the necessary import or imports.
    """
    error = None
    if isinstance(val, (list, tuple)):
        if all('.' in item for item in val):
            return [import_from_string(item, setting_name) for item in val]
        else:
            error = True
    elif "." in val:
        return import_from_string(val, setting_name)
    else:
        error = True

    if error:
        raise ImproperlyConfigured(
            "Bad value for {}: {}".format(setting_name, val)
        )


def import_from_string(val, setting_name):
    """
    Attempt to import a class from a string representation.
    """
    try:
        parts = val.split('.')
        module_path, class_name = '.'.join(parts[:-1]), parts[-1]
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    except AttributeError:
        return apps.get_model(val)
    except ImportError as err:
        msg = "Could not import '{}' for setting '{}'. {}: {}.".format(
            val, setting_name, err.__class__.__name__, err
        )
        raise ImportError(msg)


class OAuth2JWTProviderSettings(object):
    """
    A settings object, that allows OAuth2 JWT Provider settings to be accessed
    as properties.
    Any setting with string import paths will be automatically resolved
    and return the class, rather than the string literal.
    """
    # pylint: disable-msg=too-few-public-methods

    def __init__(self, user_settings=None, defaults=None, import_strings=None,
                 mandatory=None, dot_user_settings=None, dot_settings=None):
        # pylint: disable-msg=too-many-arguments
        self.user_settings = user_settings or USER_SETTINGS
        self.defaults = defaults or DEFAULTS
        self.import_strings = import_strings or IMPORT_STRINGS
        self.mandatory = mandatory or MANDATORY
        self.dot_user_settings = dot_user_settings or DOT_USER_SETTINGS
        self.dot_settings = dot_settings or DOT_SETTING_ATTRS

    def __getattr__(self, attr):
        if attr not in self.defaults.keys():
            raise AttributeError(
                "Invalid OAuth2JWTProvider setting: '{}'".format(attr)
            )

        try:
            # Check if present in user settings
            val = self.user_settings[attr]
        except KeyError:
            # Fall back to defaults
            val = self.defaults[attr]
            # Check if present in attributes that can also be set in
            # OAUTH2_PROVIDER namespaced user (not default) settings.
            if attr in self.dot_settings:
                try:
                    val = self.dot_user_settings[attr]
                except KeyError:
                    # Fall back leaves settings on jwt oauth defaults
                    pass

        # Coerce import strings into classes
        if val and attr in self.import_strings:
            val = perform_import(val, attr)

        self.validate_setting(attr, val)

        # Cache the result
        setattr(self, attr, val)
        return val

    def validate_setting(self, attr, val):
        """Ensure no mandatory settings have empty values."""
        if not val and attr in self.mandatory:
            raise AttributeError(
                "OAuth2JWTProvider setting: '{}' is mandatory".format(attr)
            )


jwt_oauth2_settings = OAuth2JWTProviderSettings(
    USER_SETTINGS, DEFAULTS, IMPORT_STRINGS, MANDATORY,
    DOT_USER_SETTINGS, DOT_SETTING_ATTRS
)
