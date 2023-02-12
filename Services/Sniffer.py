import threading, pcap, time, copy
from Base.Sniffer import Sniffer as sniffer
from Base.Packet import IP, TCP, UDP, ICMP
from Base.Packet import ARP as ARP_Layer
from Services import DHCP, ARP, DNS
from socket import inet_aton
from random import getrandbits as grb


class Sniffer:

    def __init__(self, byte_mac, out_addr, addr, mask, interface, mtu, free_ip, clients, dns_server_addr):
        self.byte_mac = byte_mac
        self.addr = addr
        self.mask = mask
        self.iface = interface
        self.mtu = mtu
        self.free_ip = free_ip
        self.clients = clients
        self._stop = False
        #self.cache = DNS.DNS_Cache(interface, (byte_mac, out_addr), addr, dns_server_addr)
        self.pcap = pcap.pcap(name=interface, immediate=True)

    def start(self, pipe, semaphore):
        # DHCP:
        threading.Thread(target=lambda:
            sniffer(filter='udp and src port 68 and dst port 67',
                    prn=lambda time, pkt:
                    self._send_packet(DHCP.dhcp_handler, pkt, self.byte_mac, self.addr, self.mask,
                                      self.free_ip, self.clients, self.mtu, pipe, semaphore),
                    stop_filter=lambda x: self._stop, iface=self.iface).start()).start()
        threading.Thread(target=lambda: self.tick(pipe, semaphore)).start()  # Handling lease.
        # ARP:
        threading.Thread(target=lambda: sniffer(filter='arp', prn=lambda time, pkt:
            self._send_packet(ARP.arp_handler, pkt, self.addr, self.byte_mac),
            stop_filter=lambda x: self._stop, iface=self.iface).start()).start()
        # DNS:
        #threading.Thread(target=lambda: sniffer(filter=f'udp and dst port 53 and dst net {self.addr}', iface=self.iface,
        #                 prn=lambda time, pkt: self._send_packet(self.cache.get_answers, (pkt,))).start()).start()
        print('Services process active!')
        pipe.send_bytes(b'\x00')

    def remove_client(self, pipe):
        while True:
            if pipe.poll(None):
                data = pipe.recv_bytes()
                self.clients[data] = (*self.clients[data][:-1], True)
                DHCP.pkt(self.byte_mac, self.addr, DHCP.force_renew(self.addr, inet_aton(self.mask),
                                             grb(32).to_bytes(4, 'big'), data, self.clients[data][0], self.mtu),
                         dst=(self.clients[data][0], data))

    def _send_packet(self, func, *args):
        pkt = func(*args)
        if hasattr(pkt, '__iter__'):
            for k in pkt:
                if k.haslayer(UDP) or k.haslayer(TCP):
                    k[2].calc_checksum(k[1].src, k[1].dst)
                elif k.haslayer(ICMP):
                    k[2].calc_checksum()
                if k.haslayer(IP):
                    k[1].calc_checksum()
                if k.haslayer(ARP_Layer) or k.payload.len <= self.mtu:
                    self.pcap.sendpacket(k.parse())
                else:
                    for i in k.fragment(self.mtu):
                        self.pcap.sendpacket(i)
            return
        if pkt is not None:
            if pkt.haslayer(UDP) or pkt.haslayer(TCP):
                pkt[2].calc_checksum(pkt[1].src, pkt[1].dst)
            elif pkt.haslayer(ICMP):
                pkt[2].calc_checksum()
            if pkt.haslayer(IP):
                pkt[1].calc_checksum()
            if pkt.haslayer(ARP_Layer) or pkt.payload.len <= self.mtu:
                self.pcap.sendpacket(pkt.parse())
            else:
                for i in pkt.fragment(self.mtu):
                    self.pcap.sendpacket(i)

    def tick(self, pipe, semaphore):
        time.sleep(1)
        keys = copy.copy(tuple(self.clients.keys()))
        new_clients = {}
        for ip in keys:
            if self.clients[ip][-1] > 1:
                new_clients[ip] = (*self.clients[ip][:-1], self.clients[ip][-1] - 1)
            elif self.clients[ip][-1] == 1:
                semaphore.acquire()
                pipe.send_bytes(b'\x00' + inet_aton(ip))
                semaphore.release()
        del keys
        self.clients = new_clients

    def stop(self):
        self._stop = True
