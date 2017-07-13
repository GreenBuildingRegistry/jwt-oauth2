#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2017 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals


def mock_as_view(view, request, *args, **kwargs):  # pragma: no cover
    """Mimic as_view() returned callable, but returns view instance.

    args and kwargs are the same you would pass to ``reverse()``
    Borrowed from: http://tech.novapost.fr/django-unit-test-your-views-en.html
    """
    view.request = request
    view.args = args
    view.kwargs = kwargs
    return view
