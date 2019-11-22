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


# q1
def num_flows(packets, sender, receiver):
    return len(get_flow(packets, sender, receiver))


# q2.1
def flow_info(packets, sender, receiver):
    flow = get_flow(packets, sender, receiver)
    for port in flow:
        transaction = {}
        takes = 0
        recv = 0
        print("For flow between ports {} -- > {}".format(port[0], port[1]))
        for packet in packets:
            if packet.src == sender and packet.des == receiver:
                if packet.syn == 0 and packet.ack == 1:
                    if packet.sport == port[0] and packet.dport == port[1] and takes <= 2:
                        transaction[packet.seqn + packet.tcpsize] = packet
                        takes += 1
            if packet.src == receiver and packet.des == sender:
                if packet.syn == 0 and packet.ack == 1:
                    if packet.sport == port[1] and packet.dport == port[0] and recv <= 2:
                        if packet.ackn in transaction:
                            print("Transaction")
                            print("{} {} {}".format(transaction[packet.ackn].seqn, transaction[packet.ackn].ackn,
                                                    transaction[packet.ackn].window))
                            print("{} {} {}".format(packet.seqn, packet.ackn, packet.window))
                            recv += 1


# q2.2
def flow_throughput(packets, sender, receiver):
    flow = get_flow(packets, sender, receiver)
    for port in flow:
        print("For flow between ports {} -- > {}".format(port[0], port[1]))
        initial_time = 0
        final_time = 0
        flag = 1
        total_size = 0
        for packet in packets:
            if packet.src == sender and packet.des == receiver:
                if packet.sport == port[0] and packet.dport == port[1]:
                    total_size += int(packet.psize)
                    if flag == 1:
                        initial_time = packet.timestamp
                        flag = 0
                    else:
                        final_time = packet.timestamp

        throughput = total_size / (final_time - initial_time)
        print(throughput)


# q2.3
def loss_rate(packets, sender, receiver):
    flow = get_flow(packets, sender, receiver)
    for port in flow:
        sequence = []
        retransmit = 0
        packetnum = 0
        print("For flow between ports {} -- > {}".format(port[0], port[1]))
        for packet in packets:
            if packet.src == sender and packet.des == receiver:
                if packet.syn == 0 and packet.ack == 1:
                    if packet.sport == port[0] and packet.dport == port[1]:
                        packetnum += 1
                        if packet.seqn not in sequence:
                            sequence.append(packet.seqn)
                        else:
                            retransmit += 1
        print(retransmit / packetnum)


# q2.4
def round_trip_time(packets, sender, receiver):
    flow = get_flow(packets, sender, receiver)
    for port in flow:
        seqndict = {}
        ackndict = {}
        print("For flow between ports {} -- > {}".format(port[0], port[1]))
        for packet in packets:
            if packet.src == sender and packet.des == receiver:
                if packet.sport == port[0] and packet.dport == port[1]:
                    length = 1
                    if packet.tcpsize > 0:
                        length = packet.tcpsize
                    if packet.seqn + length not in seqndict:
                        seqndict[packet.seqn + length] = packet.timestamp
            if packet.src == receiver and packet.des == sender:
                if packet.sport == port[1] and packet.dport == port[0]:
                    if packet.ackn not in ackndict:
                        ackndict[packet.ackn] = packet.timestamp

        total_rtt = 0
        trips = 0
        for k, v in seqndict.items():
            if k in ackndict:
                trips += 1
                total_rtt += ackndict[k] - v
        avgrtt = total_rtt / trips
        print(avgrtt)


records = open_file()
print("Number of flows")
print(num_flows(records, "130.245.145.12", "128.208.2.198"))
print()
print("Initial two transactions after connection setup")
flow_info(records, "130.245.145.12", "128.208.2.198")
print()
print("Throughpt")
flow_throughput(records, "130.245.145.12", "128.208.2.198")
print()
print("Loss Rate")
loss_rate(records, "130.245.145.12", "128.208.2.198")
print()
print("Round Trip time")
round_trip_time(records, "130.245.145.12", "128.208.2.198")
