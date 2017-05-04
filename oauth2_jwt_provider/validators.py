#!/usr/bin/env python
# encoding: utf-8
"""
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Django
from django.core.exceptions import ValidationError

# Imports from Third Party Modules
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
    load_ssh_public_key,
)
from cryptography.exceptions import UnsupportedAlgorithm


def validate_public_key(value):
    """Check that the given value is a valid RSA Public key in PEM, OpenSSH,
    or DER format. If not, raises ValidationError"""
    is_valid = False
    error = None
    pub_key_loaders = [
        load_pem_public_key, load_ssh_public_key, load_der_public_key
    ]
    for loader in pub_key_loaders:
        if not is_valid:
            try:
                loader(value.encode('utf-8'), default_backend())
                is_valid = True
                break
            except (ValueError, UnsupportedAlgorithm) as err:
                error = err
    if not is_valid:
        raise ValidationError('Public key is not valid: {}'.format(error))
