#!/usr/bin/env python
# encoding: utf-8
"""
copyright (c) 2016-2018 Earth Advantage. All rights reserved.
..codeauthor::Fable Turas <fable@raintechpdx.com>
"""

from __future__ import absolute_import, unicode_literals

# Imports from Standard Library
from datetime import datetime, timedelta
from time import mktime

# Imports from Third Party Modules
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

PRIVATE_KEY_PEM = '''
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDBCeVu627zFZ1JH9/Wi/J/bs6zC3bUFl0ASfE6XHGxyPTAPXgJ
nc7AsnRBxbNA692v1srkZr1X1BwUbzcaMRZwpGi4vO4VwzLldJC/YLFp5z6C66bg
GvRrp5pQhu4ntuHR82yS2X/IBsmMArUug9mO/LyoGthqRBVic/a9l9+INQIDAQAB
AoGBAIekj45waubuwjXW6u+UKRL4ZtAS9y2yhSklzBbpTI7TmX/X8Zg4RkbLXru0
0u+EjaL4eFskAlpL1mtZdsu1wICvyiFKuvh5WE+OwxBLpju/7AuZ9lCan9HR0X8P
EXASwU8ZFGTbLWPJePeiWl41431EAZtq/cWDSB/RQeoa2mNBAkEA5OKP+uxjSH1o
kCg+YqmlaakQ+2b8fS5J0ZyriVmoOAG0af647rsf4G3x3tXokoLXLn/620DE1HQ5
fCqI7l2xhQJBANfoNwSAqMbrURS2g4X1F6t5kxqPW7QNYrqPiAwGeXrJlG0Y8U5v
Yv73vRlnigdSJzTQOnY0FhniFWuScIdk4vECQG6iTLIfHQZnB+nWagFKuxfNjtXW
O+lOPIRDVG75lWQs/sXVSBKtBIV431a00swuzlA9sEXWks2WuEqaTMHbK/kCQQCG
3uV3Z5OG5zp4EOcqCAeoM0LERadIW1BAMCcRM/4wyLlySTF8CLKziThUJUyg9B3P
rP/IFRN1SbiNwSWQPmJRAkEAlBTPJeblIe0u/Zj8f4AKaSnKQXBvTwA3OP/FyjHR
8KaS4wpfYQvYuXZe6EDB6d6AxNxDuYn5T6D/qtVAR/eZWw==
-----END RSA PRIVATE KEY-----
'''
PUBLIC_KEY_PEM = '''
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBCeVu627zFZ1JH9/Wi/J/bs6z
C3bUFl0ASfE6XHGxyPTAPXgJnc7AsnRBxbNA692v1srkZr1X1BwUbzcaMRZwpGi4
vO4VwzLldJC/YLFp5z6C66bgGvRrp5pQhu4ntuHR82yS2X/IBsmMArUug9mO/Lyo
GthqRBVic/a9l9+INQIDAQAB
-----END PUBLIC KEY-----
'''
PUBLIC_KEY_SSH = '''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkZygR
YRJQXnjp6jq62f6XW+gmr3ufI43foqmUgPa7gm5ubw24Em2AioO59q0Ouxqtq7YG
rBU+3T0qhjV913tqpvBkvHbmhCj1405Z8PKleWFIXL08pEqttm1s6a9Z7gt5DC5C
QSet6wpHvqj7I8NZu2BEeCksiFqbzVQpT67zAP02PMn3Fb7I9EuNvktsb53Hcln1
bFTcZAxiVbAVoeNFwnZXWKmAZ0LAN05d4EjtbYmJWEeDAwCTDODTYJ/m8rlsWbsn
3fWy/gMLqfEESrERPlpgrOshP3u9IYx2AZUUgKrUjH+HJNoddouhvjfxFIrdrE31
3f2K+HIrxAPsTa83 USER@USER'''
PUBLIC_KEY = serialization.load_pem_public_key(
    PUBLIC_KEY_PEM.encode('utf-8'),
    backend=default_backend()
)
SUBJECT = 'fake user'
AUDIENCE = 'http://localhost/path'
ISSUER = "5tRI7pFJFZ2hrsF9VmpTdvdlZH5rJQt78wdcD9th"


class FakeToken(object):

    def __init__(self, key=PRIVATE_KEY_PEM, iss=ISSUER, sub=SUBJECT,
                 aud=AUDIENCE, exp="default", password=None,
                 algorithm='RS256', **kwargs):
        self.private_key = key
        self.iss = iss
        self.sub = sub
        self.aud = aud
        self.exp = exp if exp != "default" else self._get_exp()
        self.password = password
        self.algorithm = algorithm
        self.additional_claims = kwargs

    def _get_exp(self):
        now_plus_10 = datetime.now() + timedelta(minutes=10)
        return mktime(now_plus_10.timetuple())

    def _build_payload(self):
        payload = {
            "iss": self.iss,
            "sub": self.sub,
            "aud": self.aud,
            "exp": self.exp
        }
        payload.update(**self.additional_claims)
        return payload

    def _serialize_key(self):
        private_key = self.private_key.encode('utf-8')
        return serialization.load_pem_private_key(
            private_key, password=self.password, backend=default_backend()
        )

    @property
    def token(self):
        payload = self._build_payload()
        key = self._serialize_key()
        return jwt.encode(payload, key, self.algorithm).decode('utf-8')
