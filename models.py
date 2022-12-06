from exceptions import *
from utils import random_byte_message


class ICMPRequest:
    def __init__(self, destination, id, sequence, payload=None,
            payload_size=56, ttl=64, traffic_class=0):

        if payload:
            payload_size = len(payload)

        self._destination = destination
        self._id = id & 0xffff
        self._sequence = sequence & 0xffff
        self._payload = payload
        self._payload_size = payload_size
        self._ttl = ttl
        self._traffic_class = traffic_class
        self._time = 0

    def __repr__(self):
        return f'<ICMPRequest [{self._destination}]>'

    @property
    def destination(self):
        '''
        The IP address of the host to which the message should be sent.

        '''
        return self._destination

    @property
    def id(self):
        '''
        The identifier of the request.
        Used to match the reply with the request.

        '''
        return self._id

    @property
    def sequence(self):
        '''
        The sequence number.
        Used to match the reply with the request.

        '''
        return self._sequence

    @property
    def payload(self):
        '''
        The payload content in bytes.
        Return a random payload if not defined.

        '''
        return self._payload or random_byte_message(self._payload_size)

    @property
    def payload_size(self):
        '''
        The payload size.

        '''
        return self._payload_size

    @property
    def ttl(self):
        '''
        The time to live of the packet in terms of hops.

        '''
        return self._ttl

    @property
    def time(self):
        '''
        The timestamp of the ICMP request.

        Initialized to zero when creating the request and replaced by
        the `send` method of an ICMP socket with the time of sending.

        '''
        return self._time


class ICMPReply:
    '''
    A class that represents an ICMP reply. Generated from an ICMP socket.

    :type source: str
    :param source: The IP address of the host that composes the ICMP
        message.

    :type family: int
    :param family: The address family. Can be set to `4` for IPv4 or `6`
        for IPv6 addresses.

    :type id: int
    :param id: The identifier of the reply. Used to match the reply with
        the request.

    :type sequence: int
    :param sequence: The sequence number. Used to match the reply with
        the request.

    :type type: int
    :param type: The type of ICMP message.

    :type code: int
    :param code: The ICMP error code.



    :type time: float
    :param time: The timestamp of the ICMP reply.

    '''
    __slots__ = '_source', '_family', '_id', '_sequence', '_type', \
                '_code',  '_time'

    def __init__(self, source, id, sequence, type, code, time):

        self._source = source
        self._family = 4
        self._id = id
        self._sequence = sequence
        self._type = type
        self._code = code
        self._time = time

    def __repr__(self):
        return f'<ICMPReply [{self._source}]>'

    def raise_for_status(self):
        '''
        Throw an exception if the reply is not an ICMP Echo Reply.
        Otherwise, do nothing.

        :raises DestinationUnreachable: If the destination is
            unreachable for some reason.
        :raises TimeExceeded: If the time to live field of the ICMP
            request has reached zero.
        :raises ICMPError: Raised for any other type and ICMP error
            code, except ICMP Echo Reply messages.

        '''
        if self._family == 6:
            if self._type == 1:
                raise ICMPv6DestinationUnreachable(self)

            if self._type == 3:
                raise ICMPv6TimeExceeded(self)
        else:
            if self._type == 3:
                raise ICMPv4DestinationUnreachable(self)

            if self._type == 11:
                raise ICMPv4TimeExceeded(self)

        if (self._family == 4 and self._type != 0 or
            self._family == 6 and self._type != 129):
            message = f'Error type: {self._type}, code: {self._code}'
            raise ICMPError(message, self)

    @property
    def source(self):
        '''
        The IP address of the host that composes the ICMP message.

        '''
        return self._source

    @property
    def id(self):
        '''
        The identifier of the reply.
        Used to match the reply with the request.

        '''
        return self._id

    @property
    def sequence(self):
        '''
        The sequence number.
        Used to match the reply with the request.

        '''
        return self._sequence

    @property
    def type(self):
        '''
        The type of ICMP message.

        '''
        return self._type

    @property
    def code(self):
        '''
        The ICMP error code.

        '''
        return self._code



    @property
    def time(self):
        '''
        The timestamp of the ICMP reply.

        '''
        return self._time


class Host:
    '''
    A class that represents a host. It simplifies the use of the results
    from the `ping`, `multiping` and `traceroute` functions.

    :type address: str
    :param address: The IP address of the host that responded to the
        request.

    :type packets_sent: int
    :param packets_sent: The number of packets transmitted to the
        destination host.

    :type rtts: list[float]
    :param rtts: The list of round-trip times expressed in milliseconds.

    '''
    __slots__ = '_address', '_packets_sent', '_rtts'

    def __init__(self, address, packets_sent, rtts):
        self._address = address
        self._packets_sent = packets_sent
        self._rtts = rtts

    def __repr__(self):
        return f'<Host [{self._address}]>'

    def __str__(self):
        return f'  {self._address}\n' + '-' * 60 + '\n' \
               f'  Packets sent:     {self._packets_sent}\n' \
               f'  Packets received: {self.packets_received}\n' \
               f'  Packet loss:      {self.packet_loss * 100}%\n' \
               f'  Round-trip times: {self.min_rtt} ms / ' \
               f'{self.avg_rtt} ms / {self.max_rtt} ms\n' \
               f'  Jitter:           {self.jitter} ms\n' + '-' * 60

    @property
    def address(self):
        '''
        The IP address of the host that responded to the request.

        '''
        return self._address

    @property
    def min_rtt(self):
        '''
        The minimum round-trip time in milliseconds.

        '''
        if not self._rtts:
            return 0.0

        return round(min(self._rtts), 3)

    @property
    def avg_rtt(self):
        '''
        The average round-trip time in milliseconds.

        '''
        if not self._rtts:
            return 0.0

        return round(sum(self._rtts) / len(self._rtts), 3)

    @property
    def max_rtt(self):
        '''
        The maximum round-trip time in milliseconds.

        '''
        if not self._rtts:
            return 0.0

        return round(max(self._rtts), 3)

    @property
    def rtts(self):
        '''
        The list of round-trip times expressed in milliseconds.

        '''
        return self._rtts

    @property
    def packets_sent(self):
        '''
        The number of requests transmitted to the remote host.

        '''
        return self._packets_sent

    @property
    def packets_received(self):
        '''
        The number of ICMP responses received from the remote host.

        '''
        return len(self._rtts)

    @property
    def packet_loss(self):
        '''
        Packet loss occurs when packets fail to reach their destination.
        Return a `float` between 0 and 1 (all packets are lost).

        '''
        if not self._packets_sent:
            return 0.0

        return round(1 - len(self._rtts) / self._packets_sent, 2)

    @property
    def jitter(self):
        '''
        The jitter in milliseconds, defined as the variance of the
        latency of packets flowing through the network.

        At least two ICMP responses are required to calculate the
        jitter.

        '''
        sum_deltas = 0.0
        num_deltas = len(self._rtts) - 1

        if num_deltas < 1:
            return 0.0

        for i in range(num_deltas):
            sum_deltas += abs(self._rtts[i] - self._rtts[i + 1])

        return round(sum_deltas / num_deltas, 3)

    @property
    def is_alive(self):
        '''
        Indicate whether the host is reachable.
        Return a `boolean`.

        '''
        return len(self._rtts) > 0


class Hop(Host):
    '''
    A class that represents a hop. It extends the `Host` class and adds
    some features for the `traceroute` function.

    :type address: str
    :param address: The IP address of the gateway or host that responded
        to the request.

    :type packets_sent: int
    :param packets_sent: The number of packets transmitted to the
        destination host.

    :type rtts: list[float]
    :param rtts: The list of round-trip times expressed in milliseconds.

    :type distance: int
    :param distance: The distance, in terms of hops, that separates the
        remote host from the current machine.

    '''
    __slots__ = '_address', '_packets_sent', '_rtts', '_distance'

    def __init__(self, address, packets_sent, rtts, distance):
        super().__init__(address, packets_sent, rtts)
        self._distance = distance

    def __repr__(self):
        return f'<Hop {self._distance} [{self._address}]>'

    def __str__(self):
        return f'  #{self._distance:<2} {super().__str__()[2:]}'

    @property
    def distance(self):
        '''
        The distance, in terms of hops, that separates the remote host
        from the current machine.

        '''
        return self._distance
