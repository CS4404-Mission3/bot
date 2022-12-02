# FakeBot
A bot with c2 over covert channels but no malicious payload, written in python for CS4404 Mission 3.

# Communications
The communication method used by the bot and c2 system is a covert channel based on mDNS.

## Why?
The whole pont of this project is to develop a system that can go undetected by IDS systems like Bro and then build an IDS
to detect it. mDNS, Bonjour, Zeroconf, and the like are extremely noisy and common protocols, so hiding data in them
shouldn't be that hard and IDS's will probably be none the wiser (or so we hope).

## Basic Concept
The basic concept of this covert channel, hereon referred to as auRevior, is to communicate using innocuous packets and use
a form of binary data encoding based on if a packet was sent at a given time or not. The system will send up to 8 packets at once
from UDP source ports 5350-5358. Each of these source ports is a bit. The bit is 1 if the packet was sent and 0 otherwise.
Packets are sent in 0.25 second long frames allowing for a theoretical transfer rate of 4 bytes per second. This is incredibly
slow, but we don't want an IDS to think we're trying to flood the network, and our payloads are small. 

## Technical Details
### Preamble
Each transmission has a 4 byte pre-able of the pattern `0xAA 0x55 0xAA 0x55`. This indicates the transmission of a new message
and transfers the checksum of the following data. The checksum is a 16 bit field and is conveyed by the `qclass` field of the mDNS packets.
The `qclass` field has 5 valid values which indicates the class of DNS query. The first 4 of these symbols are used to encode the binary 
values 0-3. With 2 bits per packet, 4 packets per frame, and 4 frames (2 frames transmitted twice), we are able to transmit the full checksum twice.

The preamble also serves as a synchronization source, as all frames are transmitted at 0.25 second intervals after the last preamble frame.

### Post-amble
The post-amble is 1 frame of value `0xFF` and indicates the end of transmission. Each MDNS packet in the frame has a `qclass` of 1.

# Payload

The intent of c2 for this bot is to allow the controller to run commands on the targeted system. This may be seen as a 
malicious payload, but it's really just slower, worse SSH. This has not been implemented yet and is subject to change.