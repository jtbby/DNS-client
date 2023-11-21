import random
import struct


class Message:

    def __init__(self):
        self.Header = Header()
        self.Question = None
        self.fullQuery = None

    def buildQuery(self):
        dns_Header = struct.pack('!HHHHHH', self.Header.id, self.Header.flags, self.Header.qdCount, self.Header.ancount, self.Header.nscount, self.Header.arcount)  # pack the field data in Network Byte Order
        dns_Question = struct.pack('!HH', self.Question.qType, self.Question.qClass)  # pack the question field in Network Byte order
        self.fullQuery = dns_Header + self.Question.qName + dns_Question  # add the fields, qName is already packed, so just add its variable



class Header:

    def __init__(self):
        # Setup bits for line 1 by randomly generating bits
        self.id = random.randint(0, 0xFFFF)

        # Setup bits for line 2, RD = 1 for standard query
        self.flags = 0x0100 # QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0

        # Initialize line 3 as 1
        self.qdCount = 1

        self.ancount = 0x0000

        self.nscount = 0x0000

        self.arcount = 0x0000


class Question:

    def __init__(self, url):
        self.qName = bytearray()  # start with empty byte array
        self.parseUrl(url)

        self.qType = 1
        self.qClass = 1

    def parseUrl(self, url):
        labels = url.split('.')  # turn the URL to a list by separating '.'

        for label in labels:
            label_length = len(label)
            label_bytes = label.encode('ascii')
            self.qName += struct.pack('B', label_length) + label_bytes

        self.qName += b'\x00'
