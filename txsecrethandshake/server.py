
import automat
import attr
import cbor
import types
import zope

from twisted.protocols.basic import Int32StringReceiver
from twisted.internet.protocol import Factory

from nacl.signing import VerifyKey

from envelopes import SecretHandshakeEnvelopeFactory, Curve25519KeyPair, Ed25519KeyPair
from util import is_32bytes, SingleObserver
from interfaces import ISecretHandshakeMachine


@attr.s
@zope.interface.implementer(ISecretHandshakeMachine)
class ServerMachine(object):
    """
    I am server-side state machine that implements the "secret handshake",
    a cryptographic handshake protocol as described in the paper:
    Designing a Secret Handshake: Authenticated Key Exchange as a
    Capability System by Dominic Tarr
    """
    _machine = automat.MethodicalMachine()
    envelope_factory = attr.ib(validator=attr.validators.instance_of(SecretHandshakeEnvelopeFactory))
    notify_connected_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))
    send_datagram_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))
    receive_message_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))
    disconnect_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))

    # inputs

    @_machine.input()
    def start(self):
        "the machine connects"

    @_machine.input()
    def stop(self):
        "disconnet the machine"

    @_machine.input()
    def datagram_received(self, datagram):
        "the machine receives data"

    @_machine.input()
    def send(self, datagram):
        "send a datagram"

    # outputs

    @_machine.output()
    def _send_disconnect(self):
        close_command = {
            "type":"disconnect",
            }
        disconnect_envelope = self.envelope_factory.datagram_encrypt(cbor.dumps(close_command))
        self.send_datagram_handler(disconnect_envelope)
        self.disconnect_handler()

    @_machine.output()
    def _verify_client_challenge(self, datagram):
        self.envelope_factory.is_client_challenge_verified(datagram)
        envelope = self.envelope_factory.create_server_challenge()
        self.send_datagram_handler(envelope)

    @_machine.output()
    def _verify_client_auth(self, datagram):
        self.envelope_factory.verify_client_auth(datagram)
        envelope = self.envelope_factory.create_server_accept()
        self.send_datagram_handler(envelope)

    @_machine.output()
    def _send_datagram(self, datagram):
        """
        send datagram, first serialize, then encrypt and finally pass
        to our send datagram handler.
        """
        datagram_message = {
            "type": "datagram",
            "payload": datagram
            }
        datagram_envelope = self.envelope_factory.downstream_box.encrypt(cbor.dumps(datagram_message))
        self.send_datagram_handler(datagram_envelope)

    @_machine.output()
    def _receive_datagram(self, datagram):
        """
        post-handshake: decrypt received datagrams, deserialize and
        then forward datagram payload upstream if message type is
        "datagram", if type is "disconnect" then call our disconnect
        handler.
        """
        serialized_message = self.envelope_factory.downstream_box.decrypt(datagram)
        message = cbor.loads(serialized_message)
        if message["type"] == "datagram":
            self.receive_message_handler(message["payload"])
        if message["type"] == "disconnect":
            self.disconnect_handler()

    # states

    @_machine.state(initial=True)
    def unconnected(self):
        "connection not yet initiated"

    @_machine.state()
    def awaiting_challenge(self):
        "awaiting challenge envelope from client"

    @_machine.state()
    def challenge_sent(self):
        "server challenge envelope sent"

    @_machine.state()
    def connected(self):
        "accept envelope sent"

    @_machine.state()
    def disconnected(self):
        "disconnected state"

    unconnected.upon(start, enter=awaiting_challenge, outputs=[])
    awaiting_challenge.upon(datagram_received, enter=challenge_sent, outputs=[_verify_client_challenge])
    challenge_sent.upon(datagram_received, enter=connected, outputs=[_verify_client_auth])
    connected.upon(datagram_received, enter=connected, outputs=[_receive_datagram])
    connected.upon(send, enter=connected, outputs=[_send_datagram])
    connected.upon(stop, enter=disconnected, outputs=[_send_disconnect])

