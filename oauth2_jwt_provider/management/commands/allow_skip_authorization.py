#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage.
All rights reserved
..codeauthor::Fable Turas <fable@raintechpdx.com>

Management command to update Application skip_authorization attribute to
disallow skipping authorization form.
"""

# Local Imports
from oauth2_jwt_provider.management.commands._private import SkipAuthCommand


# Data Structure Definitions

# Private Functions


# Public Classes and Functions
class Command(SkipAuthCommand):
    skip_auth = True
