#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Django
from django.db import models
from django.utils import timezone
from django.utils.encoding import python_2_unicode_compatible

# Imports from Third Party Modules
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from oauth2_provider.settings import oauth2_settings

# Local Imports
from oauth2_jwt_provider.settings import jwt_oauth2_settings
from oauth2_jwt_provider.validators import PUB_KEY_LOADERS, validate_public_key


@python_2_unicode_compatible
class PublicKey(models.Model):
    """
    A PublicKey instance represents public_key belonging to a Client
    Application for use in decoding digital signatures

    Fields:

    * :attr:`application` Application instance
    * :attr:`_key` The actual public key value of type pem, ssh or der. Should
        be accessed through the key property setter and getter methods.
    * :attr:`pub_key_last_updated` Date _key value was last changed. Updated
        automatically.
    """
    application = models.OneToOneField(
        oauth2_settings.APPLICATION_MODEL,
        related_name='public_key', on_delete=models.CASCADE
    )
    _key = models.TextField(validators=[validate_public_key])
    pub_key_last_updated = models.DateTimeField()

    def __init__(self, *args, **kwargs):
        """Copy current _key value to throwaway attribute to catch updates"""
        super(PublicKey, self).__init__(*args, **kwargs)
        self.__original_key = self._key

    def save(self, *args, **kwargs):
        """Change pub_key_last_updated date if _key is changed"""
        # pylint: disable-msg=arguments-differ
        if not self.pk or self._key != self.__original_key:
            self.pub_key_last_updated = timezone.now()
        super(PublicKey, self).save(*args, **kwargs)
        self.__original_key = self._key

    @property
    def key(self):
        """Generate cryptographically serialized copy of _key"""
        pub_key = None
        if not self.is_expired:
            pub_key = None
            for loader in PUB_KEY_LOADERS:
                if not pub_key:
                    try:
                        pub_key = loader(
                            self._key.encode('utf-8'), default_backend()
                        )
                        break
                    except (ValueError, UnsupportedAlgorithm):
                        pass
        return pub_key

    @key.setter
    def key(self, value):
        """Set _key value through key property"""
        self._key = value

    @property
    def is_expired(self):
        """
        Determine if key has exceeded settings PUBLIC_KEY_EXPIRE_DAYS. Useful
        for forcing token rotation rules.
        """
        if not jwt_oauth2_settings.PUBLIC_KEY_EXPIRE_DAYS:
            return False
        else:
            delta = timezone.now() - self.pub_key_last_updated
            return delta.days >= jwt_oauth2_settings.PUBLIC_KEY_EXPIRE_DAYS

    def __str__(self):                                       # pragma: no cover
        return "{}-RSA Public Key".format(self.application)


def get_public_key_model():
    """ Return the PublicKey model that is active in this project. """
    return jwt_oauth2_settings.PUBLIC_KEY_MODEL
