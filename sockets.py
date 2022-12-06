
from struct import pack, unpack
import platform as plt
from models import ICMPReply, ICMPRequest
from utils import *
from time import time
from exceptions import *


class ICMPSocket:

    __slots__ = '_sock', '_address', '_privileged'

    _IP_VERSION = 4
    _ICMP_HEADER_OFFSET = 20
    _ICMP_HEADER_REAL_OFFSET = 20

    _ICMP_CODE_OFFSET = _ICMP_HEADER_OFFSET + 1
    _ICMP_CHECKSUM_OFFSET = _ICMP_HEADER_OFFSET + 2
    _ICMP_ID_OFFSET = _ICMP_HEADER_OFFSET + 4
    _ICMP_SEQUENCE_OFFSET = _ICMP_HEADER_OFFSET + 6
    _ICMP_PAYLOAD_OFFSET = _ICMP_HEADER_OFFSET + 8

    _ICMP_ECHO_REQUEST = 8
    _ICMP_ECHO_REPLY = 0

    def __init__(self, address=None, privileged=True):
        self._sock = None
        self._address = address

        # The Linux kernel allows unprivileged users to use datagram
        # sockets (SOCK_DGRAM) to send ICMP requests. This feature is
        # now supported by the majority of Unix systems.
        # Windows is not compatible.
        self._privileged = privileged or PLATFORM_WINDOWS

        try:
            sys_platform = plt.system().lower()
            if "windows" in sys_platform or "linux" in sys_platform:
                self._sock = self._create_socket(
                    socket.SOCK_RAW)
            else:
                self._sock = self._create_socket(
                    socket.SOCK_DGRAM)

            if address:
                self._sock.bind((address, 0))
        except OSError as err:
            if err.errno in (1, 13, 10013):
                try:
                    self._sock = self._create_socket(
                        socket.SOCK_DGRAM)
                except OSError:
                    raise SocketPermissionError(privileged)
            if err.errno in (-9, 49, 99, 10049, 11001):
                raise SocketAddressError(address)
            raise ICMPSocketError(str(err))

    def _create_socket(self, type):
        '''
        Create and return a new socket.

        '''
        return socket.socket(
            family=socket.AF_INET,
            type=type,
            proto=socket.IPPROTO_ICMP)

    def _set_ttl(self, ttl):
        '''
        Set the time to live of every IP packet originating from this
        socket.

        '''
        self._sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_TTL,
            ttl)

    def _checksum(self, data):
        sum = 0

        # TODO:
        # Compute the checksum of an ICMP packet. Checksums are used to
        # verify the integrity of packets.
        #
        # :type data: bytes
        # :param data: The data you are going to send, calculate checksum
        # according to this.
        #
        # :rtype: int
        # :returns: checksum calculated from data
        #
        # Hint: if the length of data is even, add a b'\x00' to the end of data
        # according to RFC
        n = len(data)

        for i in range(0, n - (n%2), 2):
            sum += data[i] + (data[i + 1] << 8)
        if n%2 ==1:
            sum += data[-1]
        sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)
        sum = ~sum & 0xffff
        sum= sum >> 8 | (sum << 8 & 0xff00)
        #print(sum)
        return sum

    def _check_data(self, data, checksum):

        # TODO:
        # Verify the given data with checksum of an ICMP packet. Checksums are used to
        # verify the integrity of packets.
        #
        # :type data: bytes
        # :param data: The data you received, verify its correctness with checksum
        #
        # :type checksum: int
        # :param checksum: The checksum you received, use it to verify data.
        #
        # :rtype: boolean
        # :returns: whether the data matches the checksum
        #
        # Hint: if the length of data is even, add a b'\x00' to the end of data
        # according to RFC
        return self._checksum(data)==checksum
        #return False

    def _create_packet(self, request: ICMPRequest):
        id = request.id
        sequence = request.sequence
        payload = request.payload
        checksum = 0
        # TODO:
        # Build an ICMP packet from an ICMPRequest, you can get a sequence number and
        # a payload.
        #
        # This method returns the newly created ICMP header concatenated
        # to the payload passed in parameters.
        #
		# tips: the 'checksum' in ICMP header needs to be calculated and updated
        # :rtype: bytes
        # :returns: an ICMP header+payload in bytes format
        #print(id, sequence)
        req_bytes = b'\x08\x00'+ id.to_bytes(2, byteorder='big',signed=False) + sequence.to_bytes(2, byteorder='big',signed=False) + payload
        check_sum = self._checksum(req_bytes)
        req_bytes= b'\x08\x00'+check_sum.to_bytes(2, byteorder='big',signed=False)+id.to_bytes(2, byteorder='big',signed=False) + sequence.to_bytes(2, byteorder='big',signed=False) + payload
        #print(req_bytes)
        return req_bytes

    def _parse_reply(self, packet, source, current_time):
        sequence = 0
        type = 0
        code = 0
        # TODO:
        # Parse an ICMP reply from bytes.
        #
        # Read sequence, type and code from packet 
        #
        # :type packet: bytes
        # :param packet: IP packet with ICMP as its payload
        #
        # :rtype: ICMPReply
        # :returns: an ICMPReply parsed from packet
        return ICMPReply(
            source=source,
            id=id,
            sequence=sequence,
            type=type,
            code=code,
            time=current_time)

    def send(self, request):
        '''
        Send an ICMP request message over the network to a remote host.

        This operation is non-blocking. Use the `receive` method to get
        the reply.

        :type request: ICMPRequest
        :param request: The ICMP request you have created. If the socket
            is used in non-privileged mode on a Linux system, the
            identifier defined in the request will be replaced by the
            kernel.

        :raises SocketBroadcastError: If a broadcast address is used and
            the corresponding option is not enabled on the socket
            (ICMPv4 only).
        :raises SocketUnavailableError: If the socket is closed.
        :raises ICMPSocketError: If another error occurs while sending.

        '''
        if not self._sock:
            raise SocketUnavailableError

        try:
            sock_destination = socket.getaddrinfo(
                host=request.destination,
                port=None,
                family=self._sock.family,
                type=self._sock.type)[0][4]

            packet = self._create_packet(
                request)

            self._set_ttl(request.ttl)
            # self._set_traffic_class(request.traffic_class)

            request._time = time()
            self._sock.sendto(packet, sock_destination)

            # On Linux, the ICMP request identifier is replaced by the
            # kernel with a random port number when a datagram socket is
            # used (SOCK_DGRAM). So, we update the request created by
            # the user to take this new identifier into account.
            if not self._privileged and PLATFORM_LINUX:
                request._id = self._sock.getsockname()[1]

        except PermissionError:
            raise SocketBroadcastError

        except OSError as err:
            raise ICMPSocketError(str(err))

    def receive(self, request=None, timeout=2):
        '''
        Receive an ICMP reply message from the socket.

        This method can be called multiple times if you expect several
        responses as with a broadcast address.

        :type request: ICMPRequest, optional
        :param request: The ICMP request to use to match the response.
            By default, all ICMP packets arriving on the socket are
            returned.

        :type timeout: int or float, optional
        :param timeout: The maximum waiting time for receiving the
            response in seconds. Default to 2.

        :rtype: ICMPReply
        :returns: An `ICMPReply` object representing the response of the
            desired destination or an upstream gateway. See the
            `ICMPReply` class for details.

        :raises TimeoutExceeded: If no response is received before the
            timeout specified in parameters.
        :raises SocketUnavailableError: If the socket is closed.
        :raises ICMPSocketError: If another error occurs while receiving.

        '''
        if not self._sock:
            raise SocketUnavailableError

        self._sock.settimeout(timeout)
        time_limit = time() + timeout

        try:
            while True:
                response = self._sock.recvfrom(1024)
                current_time = time()

                packet = response[0]
                source = response[1][0]

                if current_time > time_limit:
                    raise socket.timeout

                reply = self._parse_reply(
                    packet=packet,
                    source=source,
                    current_time=current_time)

                if (reply and not request or
                    reply and request.id == reply.id and
                    request.sequence == reply.sequence):
                    return reply

        except socket.timeout:
            raise TimeoutExceeded(timeout)

        except OSError as err:
            raise ICMPSocketError(str(err))

    def close(self):
        '''
        Close the socket. It cannot be used after this call.

        '''
        if self._sock:
            self._sock.close()
            self._sock = None



