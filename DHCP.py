import scapy.all as s
from socket import inet_aton


BROADCAST = 'ff:ff:ff:ff:ff:ff', '255.255.255.255'


class DHCP:

    def __init__(self, addr, mask, mac, interface):
        self.addr = addr, inet_aton(addr)
        self.mask = mask
        self.mac = mac
        self.interface = interface

    @staticmethod
    def find_ip(requested_ip, free_ip):
        if requested_ip is not None and requested_ip in free_ip:
            free_ip.remove(requested_ip)
            return requested_ip
        return free_ip.pop()

    def discover(self, cli_mac, ip, transc_id):
        s.sendp(
            (s.Ether(src=self.mac, dst=BROADCAST[0]) /
             s.IP(src=self.addr[0], dst=BROADCAST[1]) /
             s.UDP(dport=68, sport=67) /
             self.offer(transc_id, ip, cli_mac)),
            iface=self.interface)

    def offer(self, transc_id, new_ip, cli_mac, code=b'\x02'):
        data = b'\x02\x01\x06\x00%b' % transc_id + b'\x00' * 8 + new_ip + b'\x00' * 8 + cli_mac + b'\x00' * 202 + \
            b'\x63\x82\x53\x63\x35\x01%b\x36\x04%b\x33\x04\x00\x00\x0e\x10\x01\x04%b\x03\x04%b\x06\x04%b\xff' \
               % (code, self.addr[1], self.mask, self.addr[1], b'\x0a\x00\x00\x8a')
        return data

    def request(self, cli_mac, ip, transc_id):
        s.sendp(
            (s.Ether(src=self.mac, dst=BROADCAST[0]) /
             s.IP(src=self.addr[0], dst=BROADCAST[1]) /
             s.UDP(dport=68, sport=67) /
             self.acknowledge(transc_id, ip, cli_mac)),
            iface=self.interface)

    def acknowledge(self, transc_id, new_ip, cli_mac):
        return self.offer(transc_id, new_ip, cli_mac, b'\x05')
