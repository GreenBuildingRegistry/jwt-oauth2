#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
from unittest import TestCase

# Local Imports
from jwt_oauth2lib import RequestValidator, Server


class ServerEndpointTest(TestCase):
    """Server Endpoint unit tests"""

    def test_jwt_grant_attribute(self):
        """Test jwt_grant added to Server endpoint"""
        # Endpoint behaviors are thoroughly tested in oauthlib.
        # The inclusion of the jwt_grant in the Server.__init__ method,
        # represents the only change between those tests classes and
        # jwt_oauth2lib.Server.
        validator = RequestValidator()
        server = Server(validator)
        self.assertIn(
            'urn:ietf:params:oauth:grant-type:jwt-bearer', server.grant_types
        )
