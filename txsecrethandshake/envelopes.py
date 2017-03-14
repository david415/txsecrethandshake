
import attr
import types
import zope
import hashlib
import binascii

from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.bindings import crypto_scalarmult, crypto_box_afternm, crypto_sign_BYTES, crypto_box_open_afternm

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


@attr.s
class Curve25519KeyPair(object):
    """
    curve25519 key pair
    """
    private_key = attr.ib(validator=attr.validators.instance_of(PrivateKey))
    public_key = attr.ib(validator=attr.validators.instance_of(PublicKey))


@attr.s
class Ed25519KeyPair(object):
    """
    ed25519 key pair
    """
    private_key = attr.ib(validator=attr.validators.instance_of(SigningKey))
    public_key = attr.ib(validator=attr.validators.instance_of(VerifyKey))


def is_32bytes(instance, attribute, value):
    """
    validator for node_id which should be a 32 byte value
    """
    if not isinstance(value, bytes) or len(value) != 32:
        print "val is len %s" % len(value)
        raise ValueError("must be 32 byte value")


@attr.s
class SecretHandshakeEnvelopeFactory(object):
    """
    i am a factory for building cryptographic envelopes for the
    secret-handshake protocol.
    """

    application_key = attr.ib(validator=is_32bytes)
    local_ephemeral_key = attr.ib(validator=attr.validators.instance_of(Curve25519KeyPair))
    local_signing_key = attr.ib(validator=attr.validators.instance_of(Ed25519KeyPair))
    remote_longterm_pub_key = attr.ib(validator=attr.validators.instance_of(VerifyKey))

    _remote_ephemeral_pub_key = attr.ib(init=False, validator=attr.validators.instance_of(PublicKey))
    _remote_app_mac = attr.ib(init=False, validator=is_32bytes)
    _secret = attr.ib(init=False, validator=is_32bytes)
    _hashed_secret = attr.ib(init=False, validator=is_32bytes)

    def create_client_challenge(self):
        """
        on behalf of a client i create a challenge envelope, the first
        envelope in our handshake protocol
        """
        h = hmac.HMAC(self.application_key, hashes.SHA512(), backend=default_backend())
        h.update(bytes(self.local_ephemeral_key.public_key))
        client_auth_hmac = h.finalize()
        return client_auth_hmac[:32] + bytes(self.local_ephemeral_key.public_key)

    def is_client_challenge_verified(self, challenge):
        """
        this is used by the server side.
        if i can verify the challenge then return True
        otherwise return False
        """
        assert len(challenge) == 64
        mac = challenge[:32]
        remote_ephemeral_pub_key = challenge[32:64]

        h = hmac.HMAC(self.application_key[:32], hashes.SHA512(), backend=default_backend())
        h.update(bytes(remote_ephemeral_pub_key))
        new_hash = h.finalize()[:32]
        ok = new_hash == mac
        self._remote_ephemeral_pub_key = PublicKey(remote_ephemeral_pub_key)
        self._remote_app_mac = mac
        self._secret = crypto_scalarmult(
            bytes(self.local_ephemeral_key.private_key),
            remote_ephemeral_pub_key)
        self._hashed_secret = hashlib.sha256(self._secret).digest()
        return ok

    def create_server_challenge(self):
        """
        this is the challenge envelope that the server sends to the client.
        """
        # XXX correct?
        scalar_val = crypto_scalarmult(bytes(self.local_ephemeral_key.private_key), bytes(self._remote_ephemeral_pub_key))
        hmac_key = self.application_key + scalar_val
        h = hmac.HMAC(hmac_key, hashes.SHA512(), backend=default_backend())
        h.update(bytes(self.local_ephemeral_key.public_key))
        _hmac = h.finalize()
        return _hmac[:32] + bytes(self.local_ephemeral_key.public_key)

    def is_server_challenge_verified(self, challenge):
        """
        this is used by the client side to verify
        a challenge from the server.
        if verified returns True, otherwise returns False.
        """
        assert len(challenge) == 64
        mac = challenge[:32]
        remote_ephemeral_pub_key = challenge[32:64]
        scalar_val = crypto_scalarmult(bytes(self.local_ephemeral_key.private_key), bytes(remote_ephemeral_pub_key))
        hmac_key = self.application_key[:32] + scalar_val
        h = hmac.HMAC(hmac_key, hashes.SHA512(), backend=default_backend())
        h.update(bytes(remote_ephemeral_pub_key))
        new_hmac = h.finalize()[:32]
        ok = new_hmac == mac
        self._remote_ephemeral_pub_key = PublicKey(remote_ephemeral_pub_key)
        self._remote_app_mac = mac
        self._secret = crypto_scalarmult(
            bytes(self.local_ephemeral_key.private_key),
            remote_ephemeral_pub_key)
        self._hashed_secret = hashlib.sha256(self._secret).digest()
        return ok

    def create_client_auth(self):
        hasher = hashlib.sha256()
        scalar = crypto_scalarmult(bytes(self.local_ephemeral_key.private_key), bytes(self._remote_ephemeral_pub_key))
        hasher.update(scalar)
        hashed_value = hasher.digest()
        signed_message = self.local_signing_key.private_key.sign(self.application_key + bytes(self.remote_longterm_pub_key) + bytes(hashed_value))
        message_to_box = bytes(self.local_signing_key.public_key) + signed_message.signature
        scalar_remote_longterm = crypto_scalarmult(
            bytes(self.local_ephemeral_key.private_key),
            bytes(self.remote_longterm_pub_key.to_curve25519_public_key()))

        hasher = hashlib.sha256() # XXX
        hasher.update(self.application_key + scalar + scalar_remote_longterm)
        box_secret = hasher.digest()

        nonce = b"\x00" * 24
        return crypto_box_afternm(message_to_box, nonce, box_secret)

    def verify_client_auth(self, client_auth):
        scalar = crypto_scalarmult(bytes(self.local_ephemeral_key.private_key), bytes(self._remote_ephemeral_pub_key))
        scalar_remote_longterm = crypto_scalarmult(
            bytes(self.local_signing_key.private_key.to_curve25519_private_key()),
            bytes(self._remote_ephemeral_pub_key))

        hasher = hashlib.sha256()
        hasher.update(self.application_key + scalar + scalar_remote_longterm)
        box_secret = hasher.digest()

        nonce = b"\x00" * 24
        message = crypto_box_open_afternm(client_auth, nonce, box_secret)
        remote_longterm_pub_key = message[:32]
        signature = message[32:]

        hasher = hashlib.sha256()
        scalar = crypto_scalarmult(bytes(self.local_ephemeral_key.private_key), bytes(self._remote_ephemeral_pub_key))
        hasher.update(scalar)
        hashed_value = hasher.digest()

        signed_message = self.application_key + bytes(self.local_signing_key.public_key) + hashed_value
        self.remote_longterm_pub_key.verify(signed_message, signature=signature)

    # def create_server_accept(self):
    #     curve_remote_pub_key = self.remote_longterm_pub_key.to_curve25519_public_key()
    #     self._server_accept = crypto_scalarmult(bytes(self.local_ephemeral_key.private_key), bytes(curve_remote_pub_key))

    #     hasher = hashlib.sha256()
    #     hasher.update(bytes(self.application_key))
    #     hasher.update(bytes(self._secret))
