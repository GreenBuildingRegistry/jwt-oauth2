#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage.
All rights reserved
..codeauthor::Fable Turas <fable@raintechpdx.com>

[ INSERT DOC STRING ]  # TODO
"""

# Imports from Django
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import FieldDoesNotExist
from django.core.management.base import BaseCommand, CommandError

# Imports from Third Party Modules
from oauth2_provider.models import get_application_model

# Local Imports
from oauth2_jwt_provider.settings import jwt_oauth2_settings

# Setup

# Constants

User = get_user_model()
# Data Structure Definitions

# Private Functions


# Public Classes and Functions
class AddGroupCommand(BaseCommand):
    setting_name = ''
    help = """Adds user to group specified in
    OAUTH2_JWT_PROVIDER settings {}""".format(setting_name)

    def add_arguments(self, parser):                         # pragma: no cover
        parser.add_argument('username', type=str)

    def handle(self, *args, **options):
        dev_group = getattr(jwt_oauth2_settings, self.setting_name)
        if not dev_group:
            msg = """{} must be defined in OAUTH2_JWT_PROVIDER
             settings""".format(self.setting_name)
            raise CommandError(msg)
        else:
            group, _ = Group.objects.get_or_create(name=dev_group)

        try:
            user = User.objects.get(username=options['username'])
        except User.DoesNotExist:
            msg = "User {} does not exist".format(options['username'])
            raise CommandError(msg)
        else:
            user.groups.add(group)
        self.stdout.write("Successfully added {} to group {}".format(
            user.username, dev_group
        ))


class SkipAuthCommand(BaseCommand):
    skip_auth = None

    def add_arguments(self, parser):                         # pragma: no cover
        parser.add_argument('username', type=str)
        parser.add_argument(
            '-n', '--app_name',
            help="Get user's application by name",
            type=str
        )
        parser.add_argument(
            '-i', '--app_id',
            help="Get user's application by ID",
            type=str
        )

    def handle(self, *args, **options):
        Application = get_application_model()
        app_id = options['app_id']
        app_name = options['app_name']
        username = options['username']
        if not app_name and not app_id:
            msg = 'You must provide either an app name(-n) or an app id(-i)'
            CommandError(msg)

        try:
            Application._meta.get_field('skip_authorization')
        except FieldDoesNotExist:                            # pragma: no cover
            msg = "{} does not have a 'skip_authorization attribute".format(
                Application
            )
            raise CommandError(msg)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            msg = "User {} does not exist".format(username)
            raise CommandError(msg)

        if app_id:
            try:
                oauth_app = Application.objects.get(pk=app_id, user=user)
            except Application.DoesNotExist:
                msg = "{} does not have Application matching id {}".format(
                    username, app_id
                )
                raise CommandError(msg)
        else:
            try:
                oauth_app = Application.objects.get(name=app_name, user=user)
            except Application.DoesNotExist:
                msg = "{} does not have Application matching name {}".format(
                    username, app_name
                )
                raise CommandError(msg)
            except Application.MultipleObjectsReturned:
                msg = """{} has more than one Application matching name {}.
                You will need to use app_id argument
                (-i or --app_id)""".format(username, app_name)
                raise CommandError(msg)
        oauth_app.skip_authorization = self.skip_auth
        oauth_app.save()
        self.stdout.write(
            "Successfully set user's {}.skip_authorization to {}".format(
                oauth_app.name, self.skip_auth
            )
        )
