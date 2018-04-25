# Imports from Django
import django

version = django.get_version()

if version.startswith('2'):
    from django.urls import include, re_path as url
else:
    from django.conf.urls import include, url

OAUTH_NAMESPACE = 'oauth2_provider'

urlpatterns = [
    url(
        r'^oauth/',
        include('oauth2_jwt_provider.urls', namespace=OAUTH_NAMESPACE)
    )
]
