from RIP import RIPv2
import scapy.all as s

class RoutingInfo:

    def __init__(self, dst, mask, gateway, metric):
        self.network_destination = dst
        self.mask = mask
        self.gateway = gateway
        self.metric = metric


ip_to_int = lambda ip: int(ip.hex(), 16)
broadcast_addr = lambda addr, mask: (ip_to_int(addr) | ~ip_to_int(mask) & 0xffffffff).to_bytes(4, 'big')
network_addr = lambda addr, mask: (ip_to_int(addr) & ip_to_int(mask) & 0xffffffff).to_bytes(4, 'big')


class RIB:

    def __init__(self, out_addr):
        self.db = []
        self.db.append(RoutingInfo(network_addr(*out_addr), out_addr[1], b'\x00\x00\x00\x00', 1))

    def __add__(self, other):
        self.db.append(RoutingInfo(*other))

    def __sub__(self, other):
        for route in self.db:
            if (route.network_destination, route.mask) == other:
                self.db.remove(route)
                break
        return self

    def get_route(self, dst):
        result = '', 0, 16
        for route in self.db:
            if ip_to_int(route.network_destination) & ip_to_int(route.mask) == ip_to_int(dst) & ip_to_int(route.mask):
                if bin(int.from_bytes(route.mask, 'big')).count('1') > result[1] or \
                        (bin(int.from_bytes(route.mask, 'big')).count('1') == result[1] and route.metric < result[2]):
                    result = route.gateway, bin(int.from_bytes(route.mask, 'big')).count('1'), route.metric
        return result[0]


def get_next_hop(out_addr, dst, rib):
    result = rib.get_route(dst)
    if result == '':
        data = RIPv2.header() + RIPv2.entry(dst, b'\xff\xff\xff\xff', '\x00\x00\x00\x00', 16)
        pkt = s.IP(src=out_addr, dst='224.0.0.9') / s.UDP(sport=520, dport=520) / data
        response = s.srp1(pkt)
    else:
        return result
