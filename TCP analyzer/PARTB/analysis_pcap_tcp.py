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


file_path = "assignment2.pcap"


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
        self.hsize = unroll(buf, ">B", 46, 1)
        if 0x01 == 0x01 & int(flags):
            self.fin = 1
        if 0x02 == 0x02 & int(flags):
            self.syn = 1
        if 0x10 == 0x10 & int(flags):
            self.ack = 1
        if 0x08 == 0x08 & int(flags):
            self.psh = 1
        return self


def open_file():
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


def estimate_cwnd(packets, sender, receiver):
    flow = get_flow(packets, sender, receiver)
    for port in flow:
        packets_sent = 0
        transaction = {}
        takes = 0
        cwnd = []
        print("For flow between ports {} -- > {}".format(port[0], port[1]))
        for packet in packets:
            if packet.src == sender and packet.des == receiver:
                if packet.sport == port[0] and packet.dport == port[1] and packet.syn == 0:
                    transaction[packet.seqn + packet.tcpsize] = packet.tcpsize
                    packets_sent += packet.tcpsize
            if packet.src == receiver and packet.des == sender:
                if packet.sport == port[1] and packet.dport == port[0]:
                    if packet.ackn in transaction:
                        cwnd.append(packets_sent)
                        if takes == 10:
                            break
                        takes += 1
                        packets_sent = packets_sent - transaction[packet.ackn]
        print(cwnd)


def acks(packets, sender, receiver):
    flow = get_flow(packets, sender, receiver)
    for port in flow:
        print("For flow between ports {} -- > {}".format(port[0], port[1]))
        seqndict = {}
        ackndict = {}
        for packet in packets:
            if packet.src == sender and packet.des == receiver:
                if packet.sport == port[0] and packet.dport == port[1] and packet.syn == 0:
                    if packet.psh == 0:
                        acknum = packet.seqn
                        if acknum not in seqndict:
                            seqndict[acknum] = 1
                        else:
                            seqndict[acknum] += 1
            if packet.src == receiver and packet.des == sender:
                if packet.sport == port[1] and packet.dport == port[0]:
                    if packet.ackn not in ackndict:
                        ackndict[packet.ackn] = 1
                    else:
                        ackndict[packet.ackn] += 1

        tripdup = 0
        timeout = 0
        for k, v in seqndict.items():
            if v >= 2:
                if k in ackndict:
                    if ackndict[k] >= 3:
                        tripdup += 1
                    else:
                        timeout += 1
        print("Packets due to triple duplicate {}".format(tripdup))
        print("Packets due to timeout {}".format(timeout))
        print()


records = open_file()
print("Estimation of congestion window")
estimate_cwnd(records, "130.245.145.12", "128.208.2.198")
print()
print("Estimation of acks due to timeout and triple duplacte acks")
acks(records, "130.245.145.12", "128.208.2.198")
