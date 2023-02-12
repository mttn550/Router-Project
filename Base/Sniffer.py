from Base.Packet import Ethernet, ARP, IP, TCP, UDP, ICMP
from pcap import pcap


class Sniffer:

    def __init__(self, filter='ip', prn=lambda x, y: None, stop_filter=lambda x: None, iface=None):
        self.iface = iface
        self.prn = prn
        self.stop_filter = stop_filter
        self.filter = filter

    def start(self):
        sniffer = pcap(name=self.iface, promisc=True, immediate=True)
        sniffer.setfilter(self.filter)
        for time, pkt in sniffer:
            pkt = self.construct_packet(pkt)
            self.prn(time, pkt)
            if self.stop_filter(pkt): break

    @staticmethod
    def construct_packet(data):
        pkt = Ethernet(data)
        if pkt.proto == b'\x08\x06':
            pkt.payload = ARP(pkt.payload)
        elif pkt.proto == b'\x08\x00':
            pkt.payload = IP(pkt.payload)
            if pkt.payload.proto == 6:  # TCP
                pkt.payload.payload = TCP(data=pkt.payload.payload, length=pkt.payload.len - pkt.payload.hlen)
            elif pkt.payload.proto == 17:  # UDP
                pkt.payload.payload = UDP(data=pkt.payload.payload, length=pkt.payload.len - pkt.payload.hlen)
            elif pkt.payload.proto == 1:  # ICMP
                pkt.payload.payload = ICMP(data=pkt.payload.payload, length=pkt.payload.len - pkt.payload.hlen)
                if pkt.payload.payload.type not in (8, 0, 13, 14, 18, 10, 9):  # Aka, an error reporting ICMP message.
                    pkt.payload.payload.payload = IP(pkt.payload.payload.payload)
                    len, hlen = pkt.payload.payload.payload.len, pkt.payload.payload.payload.hlen
                    data = pkt.payload.payload.payload.payload
                    if pkt.payload.payload.payload.proto == 6:  # TCP
                        pkt.payload.payload.payload.payload = TCP(data=data, length=len - hlen)
                    elif pkt.payload.payload.payload.proto == 17:  # UDP
                        pkt.payload.payload.payload.payload = UDP(data=data, length=len - hlen)
                    elif pkt.payload.payload.payload.proto == 1:  # ICMP
                        pkt.payload.payload.payload.payload = ICMP(data=data, length=len - hlen)
        return pkt
