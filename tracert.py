import argparse
import sys

from models import *
from time import sleep
from sockets import *

PING_COUNT = 3  #the number of ICMP echo packet tobe sent whose initial TTL value are same  
PING_INTERVAL = 0.05
PING_TIMEOUT = 2
MAX_HOP = 30


def tracert(address, id=None):
    if is_hostname(address):
        address = resolve(address)[0]

    sock = ICMPSocket()

    id = id or unique_identifier()
    ttl = 1
    host_reached = False
    hops = []

    while not host_reached and ttl <= MAX_HOP:
        reply = None
        packets_sent = 0
        rtts = []

        ###############################
        # TODO:
        # Create ICMPRequest and send through socket,
        # then receive and parse reply,
        # remember to modify ttl when creating ICMPRequest
        #
        #
        # :type id: int
        # :param id: The identifier of ICMP Request
        #
        # :rtype: Host[]
        # :returns: ping result
        #
        # Hint: use ICMPSocket.send() to send packet and use ICMPSocket.receive() to receive
        #
        ################################
        isnotempty = False
        source = None
        for number in range(PING_COUNT):
            request = ICMPRequest(address, id, ((ttl-1)*PING_COUNT)+number, ttl=ttl)
            sock.send(request)
            packets_sent += 1
            send_time = time()
            reply = None
            try:
                reply: ICMPReply = sock.receive(request)
            except TimeoutExceeded:
                pass
            if reply:
                rtts.append((reply._time - request._time) * 1000)
                source = reply.source
                isnotempty = True

        if isnotempty:
            if (source == address):
                host_reached = True
            hop = Hop(
                address=source,
                packets_sent=packets_sent,
                rtts=rtts,
                distance=ttl)
            # print(hop.__str__())
            hops.append(hop)

        ttl += 1

    return hops


if __name__ == "__main__":
    target = sys.argv[1]
    parser = argparse.ArgumentParser(description="tracert")
    parser.add_argument('--i', type=int, default=None)
    args = parser.parse_args(sys.argv[2:])
    hops = tracert(target,args.i)
    for hop in hops:
        print(hop.__str__())
