#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Django
import django.db.models.deletion
from django.db import migrations, models

# Imports from Third Party Modules
from oauth2_provider.settings import oauth2_settings

# Local Imports
import oauth2_jwt_provider.validators


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(oauth2_settings.APPLICATION_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='PublicKey',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True,
                                        serialize=False, verbose_name='ID')),
                ('_key', models.TextField(
                    validators=[
                        oauth2_jwt_provider.validators.validate_public_key
                    ])),
                ('pub_key_last_updated', models.DateTimeField()),
                ('application', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='public_key',
                    to=oauth2_settings.APPLICATION_MODEL)
                 ),
            ],
        ),
    ]
