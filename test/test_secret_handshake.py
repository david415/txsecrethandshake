
import pytest
import binascii
import simplejson as json
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from twisted.test import proto_helpers

from txsecrethandshake.envelopes import Curve25519KeyPair, Ed25519KeyPair, SecretHandshakeEnvelopeFactory
from txsecrethandshake.client import SecretHandshakeClientFactory


def get_test_vectors():
    with open('./test/test_vectors.json','r') as f:
        json_data = f.read()
        return json.loads(json_data)

def test_handshake_envelopes():
    vectors = get_test_vectors()
    client_signing_private_key = SigningKey(binascii.a2b_base64(vectors['test1']['client_signing_priv_key']))
    client_signing_keypair = Ed25519KeyPair(
        client_signing_private_key,
        client_signing_private_key.verify_key
        )
    client_e_keypair = Curve25519KeyPair(
        PrivateKey(binascii.a2b_base64(vectors['test1']['client_ephemeral_priv_key'])),
        PublicKey(binascii.a2b_base64(vectors['test1']['client_ephemeral_pub_key']))        
        )
    server_e_keypair = Curve25519KeyPair(
        PrivateKey(binascii.a2b_base64(vectors['test1']['server_ephemeral_priv_key'])),
        PublicKey(binascii.a2b_base64(vectors['test1']['server_ephemeral_pub_key']))
    )
    server_signing_private_key = SigningKey(binascii.a2b_base64(vectors['test1']['server_signing_priv_key']))
    server_signing_keypair = Ed25519KeyPair(
        server_signing_private_key,
        server_signing_private_key.verify_key
        )

    server_envelope_factory = SecretHandshakeEnvelopeFactory(
        bytes(binascii.a2b_base64(vectors['test1']['application_key'])),
        server_e_keypair,
        server_signing_keypair,
        client_signing_keypair.public_key
    )
    client_envelope_factory = SecretHandshakeEnvelopeFactory(
        bytes(binascii.a2b_base64(vectors['test1']['application_key'])),
        client_e_keypair,
        client_signing_keypair,
        server_signing_keypair.public_key
    )

    client_challenge = client_envelope_factory.create_client_challenge()
    assert bytes(client_challenge) == binascii.a2b_base64(vectors['test1']['client_challenge'])
    assert server_envelope_factory.is_client_challenge_verified(client_challenge) == True

    server_challenge = server_envelope_factory.create_server_challenge()
    assert client_envelope_factory.is_server_challenge_verified(server_challenge) == True

    client_auth = client_envelope_factory.create_client_auth()
    server_envelope_factory.verify_client_auth(client_auth)

    server_accept = server_envelope_factory.create_server_accept()
    client_envelope_factory.verify_server_accept(server_accept)


@pytest.inlineCallbacks
def test_client_protocol():
    """
    test the secret-handshake client protocol,
    a 4-way cryptographic handshake protocol.
    """
    vectors = get_test_vectors()
    application_key = bytes(binascii.a2b_base64(vectors['test1']['application_key']))
    local_ephemeral_key = Curve25519KeyPair(
        PrivateKey(binascii.a2b_base64(vectors['test1']['client_ephemeral_priv_key'])),
        PublicKey(binascii.a2b_base64(vectors['test1']['client_ephemeral_pub_key']))
        )
    client_signing_private_key = SigningKey(binascii.a2b_base64(vectors['test1']['client_signing_priv_key']))
    local_signing_key = Ed25519KeyPair(
        client_signing_private_key,
        client_signing_private_key.verify_key
        )
    server_signing_private_key = SigningKey(binascii.a2b_base64(vectors['test1']['server_signing_priv_key']))
    remote_longterm_key = Ed25519KeyPair(
        server_signing_private_key,
        server_signing_private_key.verify_key
        )

    client_factory = SecretHandshakeClientFactory(
        application_key,
        local_ephemeral_key,
        local_signing_key,
        remote_longterm_key.public_key
    )
    protocol = client_factory.buildProtocol(None)
    transport = proto_helpers.StringTransport()

    protocol.makeConnection(transport)
    assert len(transport.value()) == 68
    transport.clear()

    #protocol.dataReceived(b"handshake vector2")
    #assert transport.value() == b"handshake vector3"
    #transport.clear()
    
    #yield protocol.when_done()
    yield
