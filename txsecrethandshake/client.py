
import automat
import attr
import cbor
import types
import zope

from envelopes import SecretHandshakeEnvelopeFactory, Curve25519KeyPair, Ed25519KeyPair
from interfaces import ISecretHandshakeMachine


@attr.s
@zope.interface.implementer(ISecretHandshakeMachine)
class ClientMachine(object):
    """
    I am client-side state machine that implements the "secret handshake",
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
    def _send_client_challenge(self):
        client_challenge = self.envelope_factory.create_client_challenge()
        self.send_datagram_handler(client_challenge)

    @_machine.output()
    def _verify_server_challenge(self, datagram):
        self.envelope_factory.is_server_challenge_verified(datagram)

        # send client auth envelope
        client_auth = self.envelope_factory.create_client_auth()
        self.send_datagram_handler(client_auth)

    @_machine.output()
    def _verify_server_accept(self, datagram):
        self.envelope_factory.verify_server_accept(datagram)
        self.notify_connected_handler()

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
        datagram_envelope = self.envelope_factory.upstream_box.encrypt(cbor.dumps(datagram_message))
        self.send_datagram_handler(datagram_envelope)

    @_machine.output()
    def _receive_datagram(self, datagram):
        """
        post-handshake: decrypt received datagrams, deserialize and
        then forward datagram payload upstream if message type is
        "datagram", if type is "disconnect" then call our disconnect
        handler.
        """
        serialized_message = self.envelope_factory.upstream_box.decrypt(datagram)
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
    def challenge_sent(self):
        "challenge envelope sent"

    @_machine.state()
    def client_auth_sent(self):
        "cleint auth envelope sent"

    @_machine.state()
    def connected(self):
        "accept envelope received"

    @_machine.state()
    def disconnected(self):
        "disconnected state"

    unconnected.upon(start, enter=challenge_sent, outputs=[_send_client_challenge])
    challenge_sent.upon(datagram_received, enter=client_auth_sent, outputs=[_verify_server_challenge])
    client_auth_sent.upon(datagram_received, enter=connected, outputs=[_verify_server_accept])
    connected.upon(datagram_received, enter=connected, outputs=[_receive_datagram])
    connected.upon(send, enter=connected, outputs=[_send_datagram])
    connected.upon(stop, enter=disconnected, outputs=[_send_disconnect])
