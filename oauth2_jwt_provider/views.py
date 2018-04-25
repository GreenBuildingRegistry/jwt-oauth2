#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Django
from django.views.generic import CreateView, UpdateView

# Imports from Third Party Modules
from braces.views import GroupRequiredMixin as BracesGroupMixin
from braces.views import LoginRequiredMixin
from oauth2_provider.models import get_application_model
from oauth2_provider.views import (
    ApplicationDelete,
    ApplicationDetail,
    ApplicationList,
    AuthorizedTokenDeleteView,
    AuthorizedTokensListView,
)

# Local Imports
from oauth2_jwt_provider.forms import ApplicationRegistrationForm
from oauth2_jwt_provider.settings import jwt_oauth2_settings

# Constants
ALLOW_SUPERUSERS = getattr(jwt_oauth2_settings, 'ALLOW_SUPERUSERS', False)
DEVELOPER_GROUP = getattr(jwt_oauth2_settings, 'DEVELOPER_GROUP', None)
TRUSTED_APP_GROUP = getattr(jwt_oauth2_settings, 'TRUSTED_OAUTH_GROUP', None)
# Data Structure Definitions


# Private Functions
class GroupRequiredMixin(BracesGroupMixin):

    def check_membership(self, groups):
        """ Check required group(s) """
        if ALLOW_SUPERUSERS and self.request.user.is_superuser:
            return True
        user_groups = self.request.user.groups.values_list("name", flat=True)
        return set(groups).intersection(set(user_groups))


class DeveloperGroupRequired(GroupRequiredMixin):
    group_required = (DEVELOPER_GROUP, TRUSTED_APP_GROUP,)


class ApplicationRegistration(LoginRequiredMixin, CreateView):
    """
    View used to register a new Application for the request.user
    """
    template_name = "oauth2_provider/application_registration_form.html"
    form_class = ApplicationRegistrationForm

    def form_valid(self, form):                              # pragma: no cover
        form.instance.user = self.request.user
        return super(ApplicationRegistration, self).form_valid(form)


class ApplicationUpdate(LoginRequiredMixin, UpdateView):
    """
    View used to update an application owned by the request.user
    """
    context_object_name = 'application'
    template_name = "oauth2_provider/application_form.html"
    form_class = ApplicationRegistrationForm

    def get_queryset(self):                                  # pragma: no cover
        return get_application_model().objects.filter(user=self.request.user)


# Public Classes and Functions


class RestrictedApplicationList(DeveloperGroupRequired, ApplicationList):
    pass


class RestrictedApplicationRegistration(DeveloperGroupRequired,
                                        ApplicationRegistration):
    pass


class RestrictedApplicationDetail(DeveloperGroupRequired, ApplicationDetail):
    pass


class RestrictedApplicationDelete(DeveloperGroupRequired, ApplicationDelete):
    pass


class RestrictedApplicationUpdate(DeveloperGroupRequired, ApplicationUpdate):
    pass


class RestrictedAuthorizedTokenDelete(DeveloperGroupRequired,
                                      AuthorizedTokenDeleteView):
    pass


class RestrictedAuthorizedTokensList(DeveloperGroupRequired,
                                     AuthorizedTokensListView):
    pass
