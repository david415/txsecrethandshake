
import attr
from twisted.protocols.basic import Int32StringReceiver
from twisted.internet.protocol import Factory
from nacl.signing import VerifyKey

from interfaces import ISecretHandshakeMachine
from envelopes import SecretHandshakeEnvelopeFactory, Curve25519KeyPair, Ed25519KeyPair
from util import is_32bytes, SingleObserver
from client import ClientMachine
from server import ServerMachine


def create_handshake_protocol(application_key, local_ephemeral_key, local_signing_key, remote_longterm_pub_key, machine_class):
    envelope_factory = SecretHandshakeEnvelopeFactory(
        application_key,
        local_ephemeral_key,
        local_signing_key,
        remote_longterm_pub_key,
    )
    client_protocol = SecretHandshakeProtocol()
    send_datagram_handler = lambda datagram: client_protocol._on_data(datagram)
    disconnect_handler = lambda: client_protocol._on_disconnect()
    notify_connected_handler = lambda: client_protocol.notify_connected()
    machine = machine_class(envelope_factory, notify_connected_handler, send_datagram_handler, disconnect_handler)
    client_protocol.register_machine(machine)
    return client_protocol


def create_client_handshake_protocol(application_key, local_ephemeral_key, local_signing_key, remote_longterm_pub_key):
    machine_class = ClientMachine
    return create_handshake_protocol(
        application_key,
        local_ephemeral_key,
        local_signing_key,
        remote_longterm_pub_key,
        machine_class)

def create_server_handshake_protocol(application_key, local_ephemeral_key, local_signing_key, remote_longterm_pub_key):
    machine_class = ServerMachine
    return create_handshake_protocol(
        application_key,
        local_ephemeral_key,
        local_signing_key,
        remote_longterm_pub_key,
        machine_class)


@attr.s
class SecretHandshakeClientFactory(object, Factory):

    application_key = attr.ib(validator=is_32bytes)
    local_ephemeral_key = attr.ib(validator=attr.validators.instance_of(Curve25519KeyPair))
    local_signing_key = attr.ib(validator=attr.validators.instance_of(Ed25519KeyPair))
    remote_longterm_pub_key = attr.ib(validator=attr.validators.instance_of(VerifyKey))

    def buildProtocol(self, addr):
        return create_client_handshake_protocol(
            self.application_key,
            self.local_ephemeral_key,
            self.local_signing_key,
            self.remote_longterm_pub_key)


@attr.s
class SecretHandshakeServerFactory(object, Factory):

    application_key = attr.ib(validator=is_32bytes)
    local_ephemeral_key = attr.ib(validator=attr.validators.instance_of(Curve25519KeyPair))
    local_signing_key = attr.ib(validator=attr.validators.instance_of(Ed25519KeyPair))
    remote_longterm_pub_key = attr.ib(validator=attr.validators.instance_of(VerifyKey))

    def buildProtocol(self, addr):
        return create_server_handshake_protocol(
            self.application_key,
            self.local_ephemeral_key,
            self.local_signing_key,
            self.remote_longterm_pub_key)


@attr.s
class SecretHandshakeProtocol(Int32StringReceiver, object):
    """
    i the server-side of the secret-handshake protocol.
    """
    _machine = attr.ib(init=False, default=None)
    _when_connected = attr.ib(init=False, default=SingleObserver())

    def register_machine(self, machine):
        assert ISecretHandshakeMachine.providedBy(machine)
        self._machine = machine

    def notify_connected(self):
        """
        this should be called by our state machine when the handshake is completed
        """
        self._when_connected.fire(None)

    def when_connected(self):
        """
        returns a deferred which fires when the 4-way handshake is completed
        """
        return self._when_connected.when_fired()

    def connectionMade(self):
        self._machine.start()

    def connectionLost(self, reason):
        # XXX todo: do something clever with the error message
        pass

    def stringReceived(self, data):
        self._machine.datagram_received(data)
        
    def _on_data(self, data):
        self.sendString(data)

    def _on_disconnect(self):
        self.transport.loseConnection()
