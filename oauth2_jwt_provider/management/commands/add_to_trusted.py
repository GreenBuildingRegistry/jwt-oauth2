#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage.
All rights reserved
..codeauthor::Fable Turas <fable@raintechpdx.com>

Management command to add user the group specified in JWT_OAUTH2_PROVIDER
TRUSTED_OAUTH_GROUP setting.
"""

# Local Imports
from oauth2_jwt_provider.management.commands._private import AddGroupCommand


# Data Structure Definitions

# Private Functions


# Public Classes and Functions
class Command(AddGroupCommand):
    setting_name = 'TRUSTED_OAUTH_GROUP'
