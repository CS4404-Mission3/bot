import csv
from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.packet import Packet
from scapy.sendrecv import sniff
import time

start = time.time()
counter = 0


def packet_handler(pkt: Packet):
    global counter
    if not pkt.haslayer("DNS") or not pkt.haslayer("UDP") or pkt["UDP"].dport != 5353 or not pkt.haslayer("IP"):
        return
    if pkt["IP"].src == get_if_addr(conf.iface):
        # ignore our own transmissions
        return
    counter += 1
    if round(time.time() - start, 2) - round(time.time() - start) == 0.00:
        with open("packetlog.csv", "w") as csvfile:
            writer = csv.writer(csvfile, "unix")
            writer.writerow(["{}".format(counter), "{}".format(round(time.time() - start))])
        counter = 0


sniff(prn=packet_handler)
