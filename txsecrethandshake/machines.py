
import automat
import attr


@attr.s
class ClientMachine(object):
    """
    I am state machine that implements the "secret handshake"
    cryptographic handshake as described in the paper: Designing a
    Secret Handshake: Authenticated Key Exchange as a Capability
    System by Dominic Tarr

    This state machine doesn't perform any IO and therefore could be
    used with a non-twisted networking API.
    """
    _machine = automat.MethodicalMachine()

    
