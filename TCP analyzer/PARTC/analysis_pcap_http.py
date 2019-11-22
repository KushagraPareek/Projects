"""
This is a second Project in  the course CSE:534
The program parses and analyzes TCP data
Author: Kushagra Pareek
SBUID:  112551443
"""

import dpkt
import struct


def unroll(buf, frmt, startpos, size):
    if len(buf) > startpos:
        return str(struct.unpack(frmt, buf[startpos:startpos + size])[0])


file_path1 = "http_1080.pcap"
file_path2 = "http_1081.pcap"
file_path3 = "http_1082.pcap"


class Packet:
    timestamp = None
    src = ""
    des = ""
    sport = 0
    dport = 0
    seqn = 0
    ackn = 0
    window = 0
    syn = 0
    ack = 0
    fin = 0
    psh = 0
    mss = 0
    hsize = 0
    psize = 0
    tcpsize = 0

    def parser(self, timestamp, buf):
        self.timestamp = timestamp
        self.src = unroll(buf, ">B", 26, 1) + "." + \
                   unroll(buf, ">B", 27, 1) + "." + \
                   unroll(buf, ">B", 28, 1) + "." + \
                   unroll(buf, ">B", 29, 1)
        self.des = unroll(buf, ">B", 30, 1) + "." + \
                   unroll(buf, ">B", 31, 1) + "." + \
                   unroll(buf, ">B", 32, 1) + "." + \
                   unroll(buf, ">B", 33, 1)
        self.sport = unroll(buf, ">H", 34, 2)
        self.dport = unroll(buf, ">H", 36, 2)
        self.seqn = int(unroll(buf, ">I", 38, 4))
        self.ackn = int(unroll(buf, ">I", 42, 4))
        self.window = unroll(buf, ">H", 48, 2)
        self.psize = len(buf)
        self.tcpsize = self.psize - 66
        flags = unroll(buf, ">H", 46, 2)
        self.hsize = (int(unroll(buf, ">B", 46, 1)) >> 4) * 4
        if 0x01 == 0x01 & int(flags):
            self.fin = 1
        if 0x02 == 0x02 & int(flags):
            self.syn = 1
        if 0x10 == 0x10 & int(flags):
            self.ack = 1
        if 0x08 == 0x08 & int(flags):
            self.psh = 1
        return self


def open_file(file_path):
    record = []
    with open(file_path, "rb") as file:
        pcap = dpkt.pcap.Reader(file)
        for timestamp, buf in pcap:
            packet = Packet()
            record.append(packet.parser(timestamp, buf))
    return record


def get_flow(packets, sender, receiver):
    flow = []
    for packet in packets:
        if packet.src == receiver and packet.des == sender:
            if packet.syn == 1 and packet.ack == 1:
                flow.append((packet.dport, packet.sport))
    return flow


def reassemble(packets, client, server):
    flow = get_flow(packets, client, server)
    for port in flow:
        requests = []
        responses = []

        for packet in packets:
            if packet.src == client and packet.des == server:
                if packet.sport == port[0] and packet.dport == port[1] and packet.syn == 0 and packet.psh == 1:
                    requests.append(packet)
            if packet.src == server and packet.des == client:
                if packet.sport == port[1] and packet.dport == port[0] and packet.syn == 0 and packet.psh == 1:
                    responses.append(packet)
        print("GET REQUEST AT")
        for req in requests:
            print("{} {} {} {}".format(req.src, req.des, req.seqn, req.ackn))
        print("HTTP RESPONSE COMPLETED AT")
        print("{} {} {} {}".format(responses[-1].src, responses[-1].des, responses[-1].seqn, responses[-1].ackn))
        print()


def connection_type():
    print("http_pcap.1080")
    print("Number of TCP connection created {}".format(
        len(get_flow(open_file(file_path1), "192.168.1.112", "34.193.77.105"))))
    print("http_pcap.1081")
    print("Number of TCP connection created {}".format(
        len(get_flow(open_file(file_path2), "192.168.1.112", "34.193.77.105"))))
    print("http_pcap.1082")
    print("Number of TCP connection created {}".format(
        len(get_flow(open_file(file_path3), "192.168.1.112", "34.193.77.105"))))


def analyze(packets):
    pack = 0
    sizedata = 0
    flag = 0
    intime = 0
    fintime = 0
    for packet in packets:
        sizedata += packet.psize
        pack += 1
        if flag == 0:
            intime = packet.timestamp
            flag = 1
        fintime = packet.timestamp
    print("Packets {}".format(pack))
    print("Raw data {}".format(sizedata))
    print("Time taken {}".format(fintime - intime))


def find_speed():
    print("http_pcap.1080")
    analyze(open_file(file_path1))
    print("http_pcap.1081")
    analyze(open_file(file_path2))
    print("Using chrome implementation")
    print("http_pcap.1082")
    analyze(open_file(file_path3))

records = open_file(file_path1)
reassemble(records, "192.168.1.112", "34.193.77.105")
connection_type()
find_speed()
