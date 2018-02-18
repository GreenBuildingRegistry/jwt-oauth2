#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Django
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

# Imports from Third Party Modules
from factory import DjangoModelFactory, Faker, SubFactory
from oauth2_provider.models import Application

User = get_user_model()


def mock_as_view(view, request, *args, **kwargs):  # pragma: no cover
    """Mimic as_view() returned callable, but returns view instance.

    args and kwargs are the same you would pass to ``reverse()``
    Borrowed from: http://tech.novapost.fr/django-unit-test-your-views-en.html
    """
    view.request = request
    view.args = args
    view.kwargs = kwargs
    return view


class UserFactory(DjangoModelFactory):
    class Meta:
        model = User

    username = Faker('user_name')


class GroupFactory(DjangoModelFactory):
    class Meta:
        model = Group

    name = Faker('name')


class ApplicationFactory(DjangoModelFactory):
    class Meta:
        model = Application

    name = Faker('name')
    user = SubFactory(UserFactory)
    client_type = 'confidential'
    authorization_grant_type = 'client-credentials'
    skip_authorization = False
