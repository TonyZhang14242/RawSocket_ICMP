import socket, asyncio

from threading import Lock
from sys import platform
from os import getpid
from re import match
from random import choices

from exceptions import NameLookupError


PID = getpid()
PLATFORM_LINUX   = platform == 'linux'
PLATFORM_MACOS   = platform == 'darwin'
PLATFORM_WINDOWS = platform == 'win32'

_lock_id = Lock()
_current_id = PID


def random_byte_message(size):
    '''
    Generate a random byte sequence of the specified size.

    '''
    sequence = choices(
        b'abcdefghijklmnopqrstuvwxyz'
        b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        b'1234567890', k=size)

    return bytes(sequence)


def unique_identifier():
    '''
    Generate a unique identifier between 0 and 65535.
    The first number generated will be equal to the PID + 1.

    '''
    global _current_id

    with _lock_id:
        _current_id += 1
        _current_id &= 0xffff

        return _current_id


def resolve(name):
    '''
    Resolve a hostname or FQDN to an IP address. Depending on the name
    specified in parameters, several IP addresses may be returned.

    This function relies on the DNS name server configured on your
    operating system.

    :type name: str
    :param name: A hostname or a Fully Qualified Domain Name (FQDN).

    :rtype: list[str]
    :returns: A list of IP addresses corresponding to the name passed as
        a parameter.

    :raises NameLookupError: If the requested name does not exist or
        cannot be resolved.

    '''
    try:

        lookup = socket.getaddrinfo(
            host=name,
            port=None,
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM)

        return [address[4][0] for address in lookup]

    except OSError:
        pass

    raise NameLookupError(name)




def is_hostname(name):
    '''
    Indicate whether the specified name is a hostname or an FQDN.
    Return a `boolean`.

    '''
    pattern = r'(?i)^([a-z0-9-]+|([a-z0-9_-]+[.])+[a-z]+)$'
    return match(pattern, name) is not None
