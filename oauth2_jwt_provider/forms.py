#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage.
All rights reserved
..codeauthor::Fable Turas <fable@raintechpdx.com>

"""

# Imports from Django
from django import forms

# Imports from Third Party Modules
from oauth2_provider.models import get_application_model

# Local Imports
from oauth2_jwt_provider.models import get_public_key_model

# Setup

# Constants

PublicKey = get_public_key_model()
# Data Structure Definitions

# Private Functions


# Public Classes and Functions

class ApplicationRegistrationForm(forms.ModelForm):
    public_key = forms.CharField(widget=forms.Textarea)

    class Meta:
        model = get_application_model()
        fields = (
            'name', 'client_id', 'client_secret', 'client_type',
            'authorization_grant_type', 'redirect_uris'
        )

    def __init__(self, *args, **kwargs):                     # pragma: no cover
        super(ApplicationRegistrationForm, self).__init__(*args, **kwargs)
        if self.instance.pk is not None:
            pub_key = PublicKey.objects.get(application_id=self.instance.pk)
            self.initial['public_key'] = pub_key._key

    def save(self, **kwargs):                                # pragma: no cover
        pub_key = self.cleaned_data.pop('public_key', None)
        oauth_app = super(ApplicationRegistrationForm, self).save()
        if pub_key:
            PublicKey.objects.update_or_create(
                application=oauth_app,
                defaults={'key': pub_key},
            )

        return oauth_app
