import scapy.all as s
import threading
from Services import DHCP, ARP


class Sniffer:

    def __init__(self, mac, addr, mask, interface, mtu, free_ip, clients):
        self.mac = mac
        self.addr = addr
        self.mask = mask
        self.iface = interface
        self.mtu = mtu
        self.free_ip = free_ip
        self.clients = clients
        self._stop = False

    def start(self):
        # DHCP:
        threading.Thread(target=lambda:
            s.sniff(filter='udp and src port 68 and dst port 67', prn=lambda pkt:
                self._send_packet(DHCP.dhcp_handler, pkt, self.mac, self.addr, self.mask, self.free_ip, self.clients),
                    stop_filter=lambda x: self._stop, iface=self.iface)).start()
        # ARP:
        threading.Thread(target=lambda: s.sniff(filter='arp', prn=lambda pkt:
            self._send_packet(ARP.arp_handler, pkt, self.addr),
                stop_filter=lambda x: self._stop, iface=self.iface)).start()

    def _send_packet(self, func, *args):
        pkt = func(*args)
        if pkt is not None:
            s.sendp(pkt, iface=self.iface)

    def stop(self):
        self._stop = True
