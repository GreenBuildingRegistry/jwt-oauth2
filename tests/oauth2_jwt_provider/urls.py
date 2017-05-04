# Imports from Django
from django.conf.urls import include, url

OAUTH_NAMESPACE = 'oauth2_provider'

urlpatterns = [
    url(
        r'^oauth/',
        include('oauth2_jwt_provider.urls', namespace=OAUTH_NAMESPACE)
    )
]
