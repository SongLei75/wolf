"""wolfssh_x509 — minimal paramiko X.509 bridge.

Backed by wolfssh_wrapper C extension (compiled from wolfssh_wrapper.c).
"""

import os
from pathlib import Path

import paramiko
from paramiko import auth_strategy

# Import C extension for X.509 identity support
import wolfssh_wrapper as _native


class _BlobCarrier:
    """Mimics paramiko public_blob interface (key_type + key_blob attrs)."""
    __slots__ = ("key_type", "key_blob")

    def __init__(self, key_type: str, key_blob: bytes):
        self.key_type = key_type
        self.key_blob = key_blob


class _WolfsshX509PKey(paramiko.PKey):
    """paramiko PKey backed by wolfssh C extension (x509 only)."""

    def __init__(self, identity):
        super().__init__()
        self._identity = identity
        self.public_blob = _BlobCarrier(
            identity.get_key_type(), identity.get_ssh_blob())

    def get_name(self):
        return self._identity.get_key_type()

    def asbytes(self):
        return self._identity.get_ssh_blob()

    def sign_ssh_data(self, data, algorithm=None):
        algo = algorithm or self._identity.get_key_type()
        return self._identity.sign(bytes(data), algo)


class _WolfsshX509AuthStrategy(auth_strategy.AuthStrategy):
    def __init__(self, username: str, keyfile: str,
                 certfile: str | None = None, cafile: str | None = None):
        super().__init__(ssh_config=None)
        identity = _native.X509Identity(keyfile=keyfile,
                                        certfile=certfile, cafile=cafile)
        self._source = auth_strategy.InMemoryPrivateKey(
            username, _WolfsshX509PKey(identity))

    def get_sources(self):
        yield self._source


def build_x509_auth_strategy(username: str, keyfile: str,
                             certfile: str | None = None,
                             cafile: str | None = None):
    return _WolfsshX509AuthStrategy(
        username=username, keyfile=os.fspath(Path(keyfile).expanduser()),
        certfile=certfile, cafile=cafile)
