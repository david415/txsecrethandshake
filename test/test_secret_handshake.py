
import pytest
import binascii
import simplejson as json
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from twisted.test import proto_helpers

from txsecrethandshake.envelopes import Curve25519KeyPair, Ed25519KeyPair, SecretHandshakeEnvelopeFactory
from txsecrethandshake.protocol import SecretHandshakeClientFactory, SecretHandshakeServerFactory, SecretHandshakeProtocol


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


    client_ephemeral_key = Curve25519KeyPair(
        PrivateKey(binascii.a2b_base64(vectors['test1']['client_ephemeral_priv_key'])),
        PublicKey(binascii.a2b_base64(vectors['test1']['client_ephemeral_pub_key']))
        )
    client_signing_private_key = SigningKey(binascii.a2b_base64(vectors['test1']['client_signing_priv_key']))
    client_signing_key = Ed25519KeyPair(
        client_signing_private_key,
        client_signing_private_key.verify_key
        )

    server_ephemeral_key = Curve25519KeyPair(
        PrivateKey(binascii.a2b_base64(vectors['test1']['server_ephemeral_priv_key'])),
        PublicKey(binascii.a2b_base64(vectors['test1']['server_ephemeral_pub_key']))
        )
    server_signing_private_key = SigningKey(binascii.a2b_base64(vectors['test1']['server_signing_priv_key']))
    server_signing_key = Ed25519KeyPair(
        server_signing_private_key,
        server_signing_private_key.verify_key
        )

    client_factory = SecretHandshakeClientFactory(
        application_key,
        client_ephemeral_key,
        client_signing_key,
        server_signing_key.public_key
    )
    client_protocol = client_factory.buildProtocol(None)
    client_transport = proto_helpers.StringTransport()

    server_factory = SecretHandshakeServerFactory(
        application_key,
        server_ephemeral_key,
        server_signing_key,
        client_signing_key.public_key
    )
    server_protocol = server_factory.buildProtocol(None)
    server_transport = proto_helpers.StringTransport()
    
    client_protocol.makeConnection(client_transport)
    server_protocol.makeConnection(server_transport)
    assert len(client_transport.value()) == 68

    server_protocol.dataReceived(client_transport.value())
    client_transport.clear()
    client_protocol.dataReceived(server_transport.value())
    server_transport.clear()
    server_protocol.dataReceived(client_transport.value())
    client_transport.clear()
    client_protocol.dataReceived(server_transport.value())
    server_transport.clear()

    yield client_protocol.when_connected()
    yield server_protocol.when_connected()

    server_transport.clear()
    client_transport.clear()

    client_protocol.messageSend("Alice was not a bit hurt, and she \
jumped up on to her feet in a moment: she looked up, but it was all \
dark overhead; before her was another long passage, and the White \
Rabbit was still in sight, hurrying down it.  There was not a moment \
to be lost: away went Alice like the wind, and was just in time to \
hear it say, as it turned a corner, 'Oh my ears and whiskers, how late \
it's getting!' She was close behind it when she turned the corner, but \
the Rabbit was no longer to be seen: she found herself in a long, low \
hall, which was lit up by a row of lamps hanging from the roof.")
    server_protocol.dataReceived(client_transport.value())
    client_transport.clear()

    server_protocol.messageSend("There were doors all round the hall, \
but they were all locked; and when Alice had been all the way down \
one side and up the other, trying every door, she walked sadly down \
the middle, wondering how she was ever to get out again.")
    client_protocol.dataReceived(server_transport.value())
    server_transport.clear()

    client_protocol.messageSend("Suddenly she came upon a little \
three-legged table, all made of solid glass; there was nothing on it \
except a tiny golden key, and Alice's first thought was that it might \
belong to one of the doors of the hall; but, alas! either the locks \
were too large, or the key was too small, but at any rate it would not \
open any of them. However, on the second time round, she came upon a \
low curtain she had not noticed before, and behind it was a little \
door about fifteen inches high: she tried the little golden key in the \
lock, and to her great delight it fitted!")
    server_protocol.dataReceived(client_transport.value())
    client_transport.clear()

    server_protocol.messageSend("Alice opened the door and found that \
it led into a small passage, not much larger than a rat-hole: she \
knelt down and looked along the passage into the loveliest garden you \
ever saw. How she longed to get out of that dark hall, and wander \
about among those beds of bright flowers and those cool fountains, but \
she could not even get her head through the doorway; 'and even if my \
head would go through,' thought poor Alice, 'it would be of very \
little use without my shoulders. Oh, how I wish I could shut up like a \
telescope! I think I could, if I only knew how to begin.' For, you \
see, so many out-of-the-way things had happened lately, that Alice had \
begun to think that very few things indeed were really impossible.")
    client_protocol.dataReceived(server_transport.value())
    server_transport.clear()
