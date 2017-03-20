
import attr
import types
import zope
import hashlib
import binascii
from Crypto.Util import number

from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.bindings import crypto_scalarmult, crypto_box_afternm, crypto_sign_BYTES, crypto_box_open_afternm
from nacl.secret import SecretBox

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

from util import is_32bytes, is_24bytes, is_VerifyKeyOrNone


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


@attr.s
class SecretHandshakeEnvelopeFactory(object):
    """
    i am a factory for building cryptographic envelopes for the
    secret-handshake protocol as described in this document:
    https://github.com/dominictarr/secret-handshake-paper
    """

    application_key = attr.ib(validator=is_32bytes)
    local_ephemeral_key = attr.ib(validator=attr.validators.instance_of(Curve25519KeyPair))
    local_signing_key = attr.ib(validator=attr.validators.instance_of(Ed25519KeyPair))
    remote_longterm_pub_key = attr.ib(validator=is_VerifyKeyOrNone)

    _remote_ephemeral_pub_key = attr.ib(init=False, validator=attr.validators.instance_of(PublicKey))
    _remote_app_mac = attr.ib(init=False, validator=is_32bytes)
    _secret = attr.ib(init=False, validator=is_32bytes)
    _hashed_secret = attr.ib(init=False, validator=is_32bytes)
    _shared_secret = attr.ib(init=False)

    def __attrs_post_init__(self):
        nonce = bytes(b"\x00" * 24)
        upstream_secret = hashlib.sha256(bytes(self._shared_secret) +
                                         bytes(self._remote_ephemeral_pub_key)).digest()
        downstream_secret = hashlib.sha256(bytes(self._shared_secret) +
                                           bytes(self.local_ephemeral_key.public_key)).digest()
        if sorted([bytes(self._remote_ephemeral_pub_key),
                   bytes(self.local_ephemeral_key.public_key)])[0] == bytes(self._remote_ephemeral_pub_key):
            self.upstream_box = BoxStream(upstream_secret, nonce)
            self.downstream_box = BoxStream(downstream_secret, nonce)
        else:
            self.downstream_box = BoxStream(upstream_secret, nonce)
            self.upstream_box = BoxStream(downstream_secret, nonce)

    def create_client_challenge(self):
        """
        on behalf of a client i create a challenge envelope, the first
        envelope in our handshake protocol, the mathematical representation
        of this cryptographic envelope is as follows:

        a_pub, hmac_{K}(a_pub)

        where:
        K = <<this is the application key>>
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
        this envelope's crypto math representation:

        b_pub, hmac_{[ K | crypto_scalarmult(b_priv, a_pub) ]}(b_pub)

        where:
        K = <<this is the application key>>
        """
        scalar = crypto_scalarmult(bytes(self.local_ephemeral_key.private_key), bytes(self._remote_ephemeral_pub_key))
        hmac_key = self.application_key + scalar
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
        """
        this is the client authentication  cryptographic envelope
        which the client sends to the server. it's mathematical
        representation is as follows:

        Box_{box_secret}(data_to_box)

        where:
        box_secret = hash([K | crypto_scalarmult(a_priv, b_pub) | crypto_scalarmult(a_priv, B_pub)])
        data_to_box = A_pub | Sign_A_priv( K | B_pub | hash(crypto_scalarmult(a_priv, b_pub)))
        K = <<this is the application key>>
        """

        hasher = hashlib.sha256()
        scalar = crypto_scalarmult(bytes(self.local_ephemeral_key.private_key), bytes(self._remote_ephemeral_pub_key))
        hasher.update(scalar)
        hashed_value = hasher.digest()
        signed_message = self.local_signing_key.private_key.sign(self.application_key + bytes(self.remote_longterm_pub_key) + bytes(hashed_value))
        message_to_box = bytes(self.local_signing_key.public_key) + signed_message.signature
        self._client_auth = message_to_box
        scalar_remote_longterm = crypto_scalarmult(
            bytes(self.local_ephemeral_key.private_key),
            bytes(self.remote_longterm_pub_key.to_curve25519_public_key()))

        hasher = hashlib.sha256() # XXX
        hasher.update(self.application_key + scalar + scalar_remote_longterm)
        box_secret = hasher.digest()

        nonce = b"\x00" * 24
        return crypto_box_afternm(message_to_box, nonce, box_secret)

    def verify_client_auth(self, client_auth):
        """
        verify the client auth crypto envelope. this operation is performed
        by the server when it receives a client auth message.
        """
        scalar = crypto_scalarmult(bytes(self.local_ephemeral_key.private_key), bytes(self._remote_ephemeral_pub_key))
        scalar_remote_longterm = crypto_scalarmult(
            bytes(self.local_signing_key.private_key.to_curve25519_private_key()),
            bytes(self._remote_ephemeral_pub_key))

        hasher = hashlib.sha256()
        hasher.update(self.application_key + scalar + scalar_remote_longterm)
        box_secret = hasher.digest()

        nonce = b"\x00" * 24
        message = crypto_box_open_afternm(client_auth, nonce, box_secret)
        self._client_vouch = message
        self.remote_longterm_pub_key = VerifyKey(message[:32])
        signature = message[32:]

        hasher = hashlib.sha256()
        scalar = crypto_scalarmult(bytes(self.local_ephemeral_key.private_key), bytes(self._remote_ephemeral_pub_key))
        hasher.update(scalar)
        hashed_value = hasher.digest()

        signed_message = self.application_key + bytes(self.local_signing_key.public_key) + hashed_value
        self.remote_longterm_pub_key.verify(signed_message, signature=signature)

    def create_server_accept(self):
        """
        create a server accept crypto envelope.
        this envelope is sent from the server to the client.
        it's math representation is the following:

        Box_{box_secret}(data_to_box)

        where:
        data_to_box = Sign_B( K | H | hash(crypto_scalarmult(b_priv, a_pub))
        box_secret = hash([ K | crypto_scalarmult(b_priv, a_pub) | crypto_scalarmult(B_priv, a_pub) | crypto_scalarmult(b_priv, A_pub) ])
        H = A_pub | Sign_A_priv( K | B_pub | hash(crypto_scalarmult(b_priv, a_pub)))
        K = <<this is the application key>>
        """
        message_to_sign = self.application_key + self._client_vouch + self._hashed_secret
        signed_message = self.local_signing_key.private_key.sign(message_to_sign)
        message_to_box = signed_message.signature
        local_longterm_sharedsecret = crypto_scalarmult(
            bytes(self.local_signing_key.private_key.to_curve25519_private_key()),
            bytes(self._remote_ephemeral_pub_key))
        remote_longterm_sharedsecret = crypto_scalarmult(
            bytes(self.local_ephemeral_key.private_key),
            bytes(self.remote_longterm_pub_key.to_curve25519_public_key()))

        to_hash = self.application_key + self._secret + local_longterm_sharedsecret + remote_longterm_sharedsecret
        hasher = hashlib.sha256()
        hasher.update(to_hash)
        box_secret = hasher.digest()
        self._shared_secret = box_secret
        nonce = b"\x00" * 24
        return crypto_box_afternm(message_to_box, nonce, box_secret)

    def verify_server_accept(self, server_accept_envelope):
        """
        this is used by the client to verify the server accept envelope
        """
        remote_longterm_sharedsecret = crypto_scalarmult(
            bytes(self.local_ephemeral_key.private_key),
            bytes(self.remote_longterm_pub_key.to_curve25519_public_key())
            )
        local_longterm_sharedsecret = crypto_scalarmult(
            bytes(self.local_signing_key.private_key.to_curve25519_private_key()),
            bytes(self._remote_ephemeral_pub_key))

        to_hash = self.application_key + self._secret + remote_longterm_sharedsecret + local_longterm_sharedsecret
        hasher = hashlib.sha256()
        hasher.update(to_hash)
        box_secret = hasher.digest()
        self._shared_secret = box_secret
        nonce = b"\x00" * 24
        signature = crypto_box_open_afternm(server_accept_envelope, nonce, box_secret)
        message = self.application_key + self._client_auth + self._hashed_secret
        self.remote_longterm_pub_key.verify(message, signature)

    def datagram_encrypt(self, datagram):
        return self.upstream_box.encrypt(datagram)

    def datagram_decrypt(self, datagram):
        return self.downstream_box.decrypt(datagram)


@attr.s
class NonceCounter(object):
    """
    a counter for nonces.
    """
    initial_value = attr.ib(validator=is_24bytes)
    size = attr.ib(validator=attr.validators.instance_of(int))
    i = attr.ib(init=False, default=None)

    def __attrs_post_init__(self):
        self.i = number.bytes_to_long(self.initial_value)

    def __call__(self):
        """
        increment and return previous value
        """
        if self.i > 2**self.size:
            # wrap around
            self.i = 0
        ii = number.long_to_bytes(self.i)
        ii = b'\x00' * (self.size - len(ii)) + ii
        self.i += 1
        if self.i == self.initial_value:
            raise Exception("NonceCounter exhausted.")
        return ii


@attr.s
class BoxStream(object):
    """
    i am a helper class for boxing datagrams in a unidirectional stream
    """
    key = attr.ib(validator=is_32bytes)
    initial_nonce = attr.ib(validator=is_24bytes)

    nonce = attr.ib(init=False, default=None)

    MAX_LEN = 4096

    def __attrs_post_init__(self):
        self.nonce = NonceCounter(self.initial_nonce, int(SecretBox.NONCE_SIZE))
        self.box = SecretBox(self.key)

    def encrypt(self, datagram):
        """
        SecretBox-encrypt the datagram and return ciphertext
        """
        assert len(datagram) < self.MAX_LEN
        encrypted_body = self.box.encrypt(datagram, nonce=self.nonce())
        return encrypted_body.ciphertext

    def decrypt(self, datagram):
        """
        given SecretBox`ed ciphertext, decrypt and return plaintext
        """
        assert len(datagram) < self.MAX_LEN
        payload = self.box.decrypt(datagram, nonce=self.nonce())
        return payload
