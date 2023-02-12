from Base.Packet import Ethernet, ARP
from socket import inet_aton


def arp_handler(pkt, addr, mac):
    if pkt[1].dst == inet_aton(addr):
        pkt.dst = pkt.src
        pkt.src = mac
        pkt[1].src, pkt[1].dst = pkt[1].dst, pkt[1].src
        pkt[1].code = 2
        pkt[1].dmac = pkt[1].smac
        pkt[1].smac = mac
        return pkt
