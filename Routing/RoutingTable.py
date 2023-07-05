from socket import inet_aton
from Base.Packet import Ethernet, ARP
from Base.Sniffer import Sniffer
from pcap import pcap
from socket import inet_ntoa
import wmi, dns.resolver


class RoutingTable:

    def __init__(self, mac, iface, out_addr, out_mask, clients):
        self.mac = mac
        self.iface = iface
        self.out_addr = out_addr
        self.out_mask = out_mask
        self.clients = clients
        self.default_gateway = inet_aton(
            wmi.WMI().query('select DefaultIPGateway from Win32_NetworkAdapterConfiguration '
                            'where IPEnabled=TRUE')[0].DefaultIPGateway[0])
        ip_to_int = lambda ip: int(ip.hex(), 16)
        self.net_addr = lambda ip, mask: inet_ntoa(bytes.fromhex(hex(ip_to_int(ip) & ip_to_int(inet_aton(mask)))[2:].zfill(8)))
        self.out_net = self.net_addr(out_addr, out_mask)

        self.forbidden = ()
        self.hosts = {}
        # Add the default gateway to the table:
        self.__getitem__(self.default_gateway)
        self.__getitem__(inet_aton(dns.resolver.Resolver().nameservers[0]))

    def __getitem__(self, addr):
        if addr in self.clients.keys():
            return self.clients[addr][0]
        if addr in self.hosts.keys():
            return self.hosts[addr]
        if self.net_addr(addr, self.out_mask) != self.out_net and self.hosts:
            return self.hosts[self.default_gateway]
        payload = ARP({'dst': addr, 'src': self.out_addr, 'smac': self.mac})
        pkt = Ethernet((self.mac, b'\xff\xff\xff\xff\xff\xff', b'\x08\x06', payload))
        handler = pcap(name=self.iface, immediate=True)
        handler.sendpacket(pkt.parse())
        handler.setfilter('arp')
        count = 0
        for time, pkt in handler:
            count += 1
            if count >= 15:
                self.forbidden = (*self.forbidden, addr)
                return None
            if pkt is None: continue
            pkt = Sniffer.construct_packet(pkt)
            if pkt.haslayer(ARP) and pkt[1].dst == self.out_addr and pkt[1].src == addr:
                self.hosts[addr] = pkt[1].smac
                return pkt[1].smac
