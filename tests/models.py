#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

from django.db import models


class NonUniqueIssuer(models.Model):
    non_unique_id = models.CharField(max_length=255)
