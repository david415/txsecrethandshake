
import automat
import attr
import cbor
import types

from twisted.protocols.basic import Int32StringReceiver
from twisted.internet.protocol import Factory

from nacl.signing import VerifyKey

from envelopes import SecretHandshakeEnvelopeFactory, Curve25519KeyPair, Ed25519KeyPair
from util import is_32bytes, SingleObserver


@attr.s
class ClientMachine(object):
    """
    I am state machine that implements the "secret handshake", a
    cryptographic handshake protocol as described in the paper:
    Designing a Secret Handshake: Authenticated Key Exchange as a
    Capability System by Dominic Tarr
    """
    _machine = automat.MethodicalMachine()
    envelope_factory = attr.ib(validator=attr.validators.instance_of(SecretHandshakeEnvelopeFactory))
    notify_connected_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))
    send_datagram_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))
    disconnect_handler = attr.ib(validator=attr.validators.instance_of(types.FunctionType))

    # inputs

    @_machine.input()
    def connect(self):
        "the machine connects"

    @_machine.input()
    def disconnect(self):
        "disconnet the machine"

    @_machine.input()
    def datagram_received(self, datagram):
        "the machine receives data"
    
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
        datagram_message = {
            "type": "datagram",
            "payload": datagram
            }
        datagram_envelope = self.envelope_factory.datagram_encrypt(cbor.dumps(datagram_message))
        self.send_datagram_handler(datagram_envelope)

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

    unconnected.upon(connect, enter=challenge_sent, outputs=[_send_client_challenge])
    challenge_sent.upon(datagram_received, enter=client_auth_sent, outputs=[_verify_server_challenge])
    client_auth_sent.upon(datagram_received, enter=connected, outputs=[_verify_server_accept])
    connected.upon(disconnect, enter=disconnected, outputs=[_send_disconnect])


@attr.s
class SecretHandshakeClientFactory(object, Factory):

    application_key = attr.ib(validator=is_32bytes)
    local_ephemeral_key = attr.ib(validator=attr.validators.instance_of(Curve25519KeyPair))
    local_signing_key = attr.ib(validator=attr.validators.instance_of(Ed25519KeyPair))
    remote_longterm_pub_key = attr.ib(validator=attr.validators.instance_of(VerifyKey))

    def buildProtocol(self, addr):
        envelope_factory = SecretHandshakeEnvelopeFactory(
            self.application_key,
            self.local_ephemeral_key,
            self.local_signing_key,
            self.remote_longterm_pub_key,
        )
        client_protocol = SecretHandshakeClientProtocol()
        send_datagram_handler = lambda datagram: client_protocol._on_data(datagram)
        disconnect_handler = lambda: client_protocol._on_disconnect()
        notify_connected_handler = lambda: client_protocol.notify_connected()
        machine = ClientMachine(envelope_factory, notify_connected_handler, send_datagram_handler, disconnect_handler)
        client_protocol.register_machine(machine)
        return client_protocol


@attr.s
class SecretHandshakeClientProtocol(Int32StringReceiver, object):
    """
    i am a client implementing the secret-handshake cryptographic
    capability protocol

    this class design was directly inspired by meejah's txtorcon's
    _TorSocksProtocol class
    """
    _machine = attr.ib(init=False, validator=attr.validators.instance_of(ClientMachine))
    _when_connected = attr.ib(init=False, default=SingleObserver())

    def register_machine(self, machine):
        self._machine = machine

    def notify_connected(self):
        """
        this should be called by our state machine when the handshake is completed
        """
        self._when_connected.fire()

    def when_connected(self):
        """
        returns a deferred which fires when the 4-way handshake is completed
        """
        return self._when_done.when_fired()

    def connectionMade(self):
        self._machine.connect()

    def connectionLost(self, reason):
        self._machine.disconnected(SecretHandshakeError(reason))

    def stringReceived(self, data):
        self._machine.datagram_received(data)
        
    def _on_data(self, data):
        self.sendString(data)

    def _on_disconnect(self):
        self.transport.loseConnection()
