#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Third Party Modules
from braces.views import GroupRequiredMixin
from oauth2_provider.views import (
    ApplicationDelete,
    ApplicationDetail,
    ApplicationList,
    ApplicationRegistration,
    ApplicationUpdate,
    AuthorizedTokenDeleteView,
    AuthorizedTokensListView,
)


# Constants

# Data Structure Definitions

# Private Functions


# Public Classes and Functions
class DeveloperGroupRequired(GroupRequiredMixin):
    group_required = 'developer'


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
