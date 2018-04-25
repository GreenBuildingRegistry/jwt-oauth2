JWT OAuth2
==========

JWT OAuth (rfc7523) implementation provided by extending oauthlib and Django OAuth Toolkit.

The JWT OAuth 2.0 bearer token flow, as defined by RFC 7523, describes how a JWT can be used to request an OAuth access token from a suitably configured provider.

Through jwt_oauth2lib, JWT OAuth2 extends and mirrors the well written and spec compliant OAuthLib package in order provide jwt flow functionality via generic, framework agnostic, utilities.

Through oauth2_jwt_provider, JWT OAuth2 takes advantage of the excellent Django OAuth Toolkit package to ease the way into configuring your OAuth 2.0 provider to accept JWT access token requests.


Installation
------------
``pip install jwt-oauth2``

JWT OAuth2 only installs the requirements for jwt_oauth2lib, since Django and related packages are not required to use the lib or the jwt_client.

**To use the Django based OAuth Provider (oauth2_jwt_provider)**

**Install the following dependencies**::

    django >= 1.8
    django-oauth-toolkit==0.12.0
    django-braces>=1.11.0

Note: installing django-oauth-toolkit > 0.12.0 will cause Django to be updated to >= 1.10.

Add oauth2_provider and oauth2_jwt_provider to your INSTALLED_APPS


    .. code-block:: python
        INSTALLED_APPS = (
            ...
            'oauth2_provider',
            'oauth2_jwt_provider',
        )

Add OAuth2Authentication to REST_FRAMEWORK namespaces settings and/or to authentication_classes on individual api views:


    .. code-block:: python
        REST_FRAMEWORK = {
            'DEFAULT_AUTHENTICATION_CLASSES': (
                'oauth2_provider.ext.rest_framework.OAuth2Authentication',
                ...
            ),
        }

Add value for JWT_AUDIENCE to OAUTH2_JWT_PROVIDER namespaces settings in your project settings file. This is commonly the token endpoint URL of the authorization server.
See also: `RFC7523 section  <https://tools.ietf.org/html/rfc7523#section-3>`_


    .. code-block:: python
        OAUTH2_JWT_PROVIDER = {
            'JWT_AUDIENCE': 'https://example.com/oauth/token/'
        }

Add OAuth2 Provider urls to your project urls.py


    .. code-block:: python
        urlpatterns = [
            ...
            url(r'^oauth/', include('oauth2_jwt_provider.urls', namespace='oauth2_provider')),
        ]

**Sync your database**::

    $ python manage.py migrate oauth2_jwt_provider

For additional settings options and documentation for using other OAuth2 flow types, refer to `Django OAuth Toolkit <https://django-oauth-toolkit.readthedocs.io>`_


Documentation
-------------

**oauth2_jwt_provider Django usage:**

Client users/apps must register an Application before using the Authorization Server.  Access to the Application registration views is limited by the DEVELOPER_GROUP, TRUSTED_OAUTH_GROUP, or ALLOW_SUPERUSERS settings.

Providers must register group names in settings OR set ALLOW_SUPERUSERS to True.


.. code-block:: python
        OAUTH2_JWT_PROVIDER = {
            'DEVELOPER_GROUP': 'developers',
            'TRUSTED_OAUTH_GROUP': 'trusted_developers',
            'ALLOW_SUPERUSERS': False
        }


Management commands have been provided to simplify adding client users to desired developer groups.::

        ./manage.py add_to_developers [username]
        ./manage.py add_to_trusted [username]

Client users only need to be added to one group or the other.

Members of the DEVELOPER_GROUP will have access to all Application registration views, but will be required to complete an authorization step for most OAuth flows.
Adding a client user to the TRUSTED_OAUTH_GROUP will allow the authorization step to be skipped when requesting offline access.

Control of a client application's ability to skip authorization can also be controlled via the following management commands::

        ./manage.py allow_skip_authorization [username] --app_name=[application name] (or --app_id=[application id])
        ./manage.py revoke_skip_authorization [username] --app_name=[application name] (or --app_id=[application id])

To register a client Application, point your browser to the base namespaced application url as defined by your urls.py::

    https://example.com/oauth/applications/

Or use the management command to create new applications at the command line::

	./manage.py add_application [username] [application_name] [--client_type](optional, default=confidential) [--grant_type](optional, default=authorization-grant) [--redirect_uri](optional) [--public_key](optional)

In order to use the JWT Grant Flow, you MUST supply a valid public ssh key.


**jwt_oauth2lib Client side setup:**

A JWTGrantClient class has been provided for creating the jwt token and related params to RFC 7523 specs.

While this class can be used as is by supplying 'audience' and 'assertion_validator' key word args on instantiation, it is recommended that it be subclassed to set defaults for 'validator_class', 'audience', 'token_scope', 'token_url', and 'expiration_seconds'. In addition, since jwt_oauth2 aims to be generic and framework agnostic, subclassing is also necessary to create functionality in the access token retrieval methods (get_access_token, and _check_token_response) using your preferred requests library.

You will also need to implement an AssertionValidator to provide client side validation of claims to be included in the JWT. See jwt_oauth2lib/rfc7523/clients/assertion_validator.py for required methods.

Contributing
------------

License
-------
JWT OAUTH2 is released under the terms of the BSD license. Full details in LICENSE file.

Changelog
---------
JWT OAuth2 was developed for use in the greenbuilding registry project for use in interacting with the SEED Platform API v2.1.1

Upgrading this package to the latest version of Django OAuth Toolkit will be considered once the impact of the upgrade on the SEED Platform Django project can be analysed.

JWT OAuth2 is in active development.

For a full changelog see `CHANGELOG.rst <https://github.com/GreenBuildingRegistry/jwt_oauth2/blob/master/CHANGELOG.rst>`_.
