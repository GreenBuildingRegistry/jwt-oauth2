#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

# Imports from Django
from django.apps import AppConfig

# Imports from Third Party Modules
from oauth2_provider.settings import oauth2_settings

# Local Imports
from oauth2_jwt_provider.settings import jwt_oauth2_settings


class Oauth2JwtProviderConfig(AppConfig):
    """AppConfig for oauth2_jwt_provider django plugin"""
    name = 'oauth2_jwt_provider'
    verbose_name = "Django JWT OAuth Provider"

    def ready(self):
        # Push user setting or JWT OAuth defaults into DOT settings to limit
        # the number of settings, and settings namespaces, user must change.
        oauth2_settings.SCOPES = jwt_oauth2_settings.SCOPES
        oauth2_settings.OAUTH2_SERVER_CLASS = jwt_oauth2_settings.OAUTH2_SERVER_CLASS
        oauth2_settings.OAUTH2_VALIDATOR_CLASS = jwt_oauth2_settings.OAUTH2_VALIDATOR_CLASS
