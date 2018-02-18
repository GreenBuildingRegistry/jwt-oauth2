#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Django
from django.db import migrations, models

# Local Imports
from oauth2_jwt_provider.settings import jwt_oauth2_settings

DEVELOPER_GROUP = getattr(jwt_oauth2_settings, 'DEVELOPER_GROUP', None)
TRUSTED_APP_GROUP = getattr(jwt_oauth2_settings, 'TRUSTED_OAUTH_GROUP', None)


def add_developers_group(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    if DEVELOPER_GROUP:
        Group.objects.get_or_create(name=DEVELOPER_GROUP)
    if TRUSTED_APP_GROUP:
        Group.objects.get_or_create(name=TRUSTED_APP_GROUP)


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('oauth2_jwt_provider', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(add_developers_group)
    ]
