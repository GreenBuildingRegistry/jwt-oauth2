# Imports from Django
from django.apps import AppConfig
from oauth2_provider.settings import oauth2_settings
from oauth2_jwt_provider.settings import jwt_oauth2_settings


class Oauth2JwtProviderConfig(AppConfig):
    name = 'oauth2_jwt_provider'
    verbose_name = "Django JWT OAuth Provider"

    def ready(self):
        # Push user setting or JWT OAuth defaults into DOT settings to limit
        # the number of settings, and settings namespaces, user must change.
        oauth2_settings.SCOPES = jwt_oauth2_settings.SCOPES
        oauth2_settings.OAUTH2_SERVER_CLASS = jwt_oauth2_settings.OAUTH2_SERVER_CLASS
        oauth2_settings.OAUTH2_VALIDATOR_CLASS = jwt_oauth2_settings.OAUTH2_VALIDATOR_CLASS
