from scapy.layers.l2 import Ether, ARP


def arp_handler(pkt, addr):
    if pkt[ARP].pdst == addr:
        res = Ether() / ARP(op=2)
        res[ARP].pdst = pkt[ARP].psrc
        res[ARP].hwdst = pkt[ARP].hwsrc
        res[ARP].psrc = addr
        res[Ether].dst = pkt[Ether].src
        return res
