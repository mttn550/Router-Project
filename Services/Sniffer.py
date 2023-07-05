import threading, pcap, time, copy
from Base.Sniffer import Sniffer as sniffer
from Base.Packet import IP, TCP, UDP, ICMP
from Base.Packet import ARP as ARP_Layer
from Services import DHCP, ARP, DNS
from socket import inet_aton, inet_ntoa


class Sniffer:

    def __init__(self, byte_mac, out_addr, addr, mask, interface, mtu, lease_time, free_ip, clients, dns_server_addr, dns_name):
        self.byte_mac = byte_mac
        self.addr = addr
        self.mask = mask
        self.iface = interface
        self.mtu = mtu
        self.lease_time = lease_time
        self.free_ip = free_ip
        self.clients = clients
        self._stop = False
        self.dns_name = dns_name
        self.cache = DNS.DNS_Cache(interface, (byte_mac, out_addr), addr, dns_server_addr, dns_name)
        self.pcap = pcap.pcap(name=interface, immediate=True)

    def start(self, pipe, semaphore):
        # DHCP:
        threading.Thread(target=lambda:
            sniffer(filter='udp and src port 68 and dst port 67',
                    prn=lambda time, pkt:
                    self._send_packet(DHCP.dhcp_handler, pkt, self.byte_mac, self.addr, self.mask,
                                      self.free_ip, self.clients, self.mtu, self.lease_time, self.dns_name, pipe, semaphore),
                    stop_filter=lambda x: self._stop, iface=self.iface).start()).start()
        threading.Thread(target=lambda: self.tick(pipe, semaphore)).start()  # Handling lease.
        threading.Thread(target=lambda: self.remove_client(pipe)).start()  # Handling force release.
        # ARP:
        threading.Thread(target=lambda: sniffer(filter='arp', prn=lambda time, pkt:
            self._send_packet(ARP.arp_handler, pkt, self.addr, self.byte_mac),
            stop_filter=lambda x: self._stop, iface=self.iface).start()).start()
        # DNS:
        threading.Thread(target=lambda: sniffer(filter=f'udp and dst port 53 and dst net {self.addr}', iface=self.iface,
                         prn=lambda time, pkt: self._send_packet(self.cache.get_answers, (pkt,))).start()).start()
        print('Services process active!')
        pipe.send_bytes(b'\x00')

    def remove_client(self, pipe):
        while True:
            if pipe.poll(None):
                data = pipe.recv_bytes()
                # self.clients[inet_ntoa(data)] = (*self.clients[inet_ntoa(data)][:-1], True)
                # pkt = DHCP.packet(self.byte_mac, self.addr, DHCP.force_renew(self.addr, inet_aton(self.mask),
                #                     grb(32).to_bytes(4, 'big'), data,
                #                     self.clients[inet_ntoa(data)][0], self.mtu, self.lease_time),
                #                   dst=(self.clients[inet_ntoa(data)][0], data))
                # self._send_packet(lambda x: x, pkt)
                if data[:4] == b'DNS1':  # Update custom domains
                    data = data[4:]
                    if not data:
                        self.cache.custom_data = {}
                        continue
                    domain, num = DNS.DNS.get_addr_from_bytes(data, data)
                    addr = inet_ntoa(data[num + 1:])
                    self.cache.add_custom_domain(domain, (b'\x00\x01', domain, addr))
                elif data[:4] == b'DNS2':  # Updating blacklist
                    data = data[4:]
                    domain, _ = DNS.DNS.get_addr_from_bytes(data, data)
                    if domain in self.cache.blacklist:
                        self.cache.blacklist.remove(domain)
                    else:
                        self.cache.blacklist.append(domain)
                elif inet_ntoa(data) in self.clients.keys():
                    del self.clients[inet_ntoa(data)]
                elif data in self.free_ip:
                    self.free_ip.remove(data)
                elif data not in self.free_ip:
                    self.free_ip.add(data)

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
