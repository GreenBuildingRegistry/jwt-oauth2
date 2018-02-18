#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage.
All rights reserved
..codeauthor::Fable Turas <fable@raintechpdx.com>

Management command to create OAuth application for user if user is in group
from JWT_OAUTH2_PROVIDER DEVELOPER_GROUP or TRUSTED_OAUTH_GROUP setting.
"""
import sys
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

# Imports from Third Party Modules
from oauth2_provider.models import get_application_model

# Local Imports
from oauth2_jwt_provider.models import get_public_key_model
from oauth2_jwt_provider.settings import jwt_oauth2_settings

# Setup

# Constants
Application = get_application_model()

PublicKey = get_public_key_model()

User = get_user_model()

CLIENT_TYPES = ('confidential', 'public')
GRANT_TYPES = (
    'authorization-code', 'implicit', 'password', 'client-credentials'
)
DEVELOPER_GROUP = getattr(jwt_oauth2_settings, 'DEVELOPER_GROUP', None)
TRUSTED_APP_GROUP = getattr(jwt_oauth2_settings, 'TRUSTED_OAUTH_GROUP', None)
# Data Structure Definitions

# Private Functions


# Public Classes and Functions
class Command(BaseCommand):
    help = """Creates an OAuth2 Application for the specified user"""

    def add_arguments(self, parser):                         # pragma: no cover
        parser.add_argument('username', type=str)
        parser.add_argument('application_name', type=str)
        parser.add_argument(
            '-c', '--client_type',
            help="Specify client_type (default is confidential)",
            default='confidential',
            choices=CLIENT_TYPES,
            type=str
        )
        parser.add_argument(
            '-g', '--grant_type',
            help="Specify grant_type (default is authorization-code)",
            default='authorization-code',
            choices=GRANT_TYPES,
            type=str
        )
        print(sys.argv)
        parser.add_argument(
            '-r', '--redirect_uri',
            help=(
                "Set a redirect_uri, required for implicit and authorization "
                "grant types"
            ),
            type=str
        )
        parser.add_argument(
            '-k', '--public_key',
            help="Set public key for use in JWT signature validation"
        )

    def handle(self, *args, **options):
        app_name = options['application_name']
        try:
            user = User.objects.get(username=options['username'])
        except User.DoesNotExist:
            msg = "User {} does not exist".format(options['username'])
            raise CommandError(msg)

        user_groups = [group.name for group in user.groups.all()]
        dev_groups = [
            group for group in (TRUSTED_APP_GROUP, DEVELOPER_GROUP) if group
        ]
        if not dev_groups:
            msg = (
                "{} or {} must be defined in OAUTH2_JWT_PROVIDER settings"
            ).format('DEVELOPER_GROUP', 'TRUSTED_OAUTH_GROUP')
            raise CommandError(msg)
        if not any(group in user_groups for group in dev_groups):
            msg = (
                'User must belong to a developer group ({})'
                ' to create an OAuth app'.format(*dev_groups)
            )
            raise CommandError(msg)

        app, _ = Application.objects.get_or_create(
            user=user, name=app_name,
            client_type=options['client_type'],
            authorization_grant_type=options['grant_type'],
            redirect_uris=(options['redirect_uri'],)
        )
        pub_key = options['public_key']
        if pub_key:
            PublicKey.objects.update_or_create(
                application=app,
                defaults={'key': pub_key},
            )
        self.stdout.write(
            "Successfully setup OAuth application {} with client_id: {}, "
            "client_secret: {}".format(
                app_name, app.client_id, app.client_secret
            )
        )
