from Base.Packet import Ethernet, IP, TCP, UDP, ICMP
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from Routing import Rules
from socket import inet_aton
from threading import Lock
import scapy_p0f as p0f
from scapy.layers.inet import Ether

ICMP_TYPES = {0: 8, 14: 13, 18: 18, 9: 10}


def find_free_port(type):
    if type == 'tcp':
        s1 = socket(AF_INET, SOCK_STREAM)
    else:
        s1 = socket(AF_INET, SOCK_DGRAM)
    s1.bind(('', 0))
    port = s1.getsockname()[1]
    return port, s1


def fragmentation_needed(data, mtu):
    return ICMP({'code': 1, 'type': 4, 'seq': mtu.to_bytes(2, 'big'), 'data': data})

#def host_unreachable(mac, dmac, addr, dst):
#    return Ether(src=mac, dst=dmac) / IP(src=addr, dst=dst) / ICMP(type=3, code=1)


def handler(pkt, addr, out_addr, mac, routing_table, clients, rules:Rules):
    """
    Shuttle Tydirium, what is your cargo and destination?

    :param pkt: The sniffed packet.
    :param addr: The router's NAT IP address.
    :param out_addr: The computer's IP address.
    :param mac: This computer's MAC address.
    :param routing_table: The virtual router's routing table.
    :param clients: The clients' MAC and IP addresses.
    :param rules: The forwarding rules.
    :return: The packet to be routed.
    """

    dmac, dst = pkt.dst, pkt[1].dst
    names = {TCP: 'tcp', UDP: 'udp', ICMP: 'icmp'}

    if not pkt.ig_bit():  # Unicast

        if dst not in (inet_aton(addr), out_addr):  # Routing out of the virtual network.

            if type(pkt[2]) in (UDP, TCP):
                #if type(pkt[2]) == TCP and pkt[2].flags['S'] == '1':
                #    print(p0f.p0f(Ether(pkt.parse())))
                smac, src, sport = pkt.src, pkt[1].src, pkt[2].sport
                dst, dport = pkt[1].dst, pkt[2].dport
                name = names[type(pkt[1].payload)]
                new = False
                if src in clients.keys():
                    with Lock():
                        rule = rules[name, (dst, dport), sport, 1]
                        if rule is None:
                            new = True
                            if name == 'udp' or (name == 'tcp' and pkt[2].flags['S'] == '1'):
                                port, sock = find_free_port(name)
                                rules[name, (dst, dport)] = (src, sport, port, sock)
                                pkt[2].sport = port
                            else: return None
                        else:

                            pkt[2].sport = rule[-2].getsockname()[1]
                    pkt[1].src = out_addr
                pkt.src = mac
                route_mac = routing_table[dst]
                if route_mac is None: return None
                pkt.dst = route_mac
                pkt[2].calc_checksum(pkt[1].src, pkt[1].dst)
                pkt[1].calc_checksum()
                return pkt, new

            elif pkt.haslayer(ICMP):
                smac, src, dst, ptype, seq = pkt.src, pkt[1].src, pkt[1].dst, pkt[2].type, pkt[2].seq
                if src in clients.keys():
                    rules['icmp', (dst, ptype, seq)] = (src, None)
                    pkt[1].src = out_addr
                pkt.src = mac
                pkt.dst = routing_table[dst]
                pkt[2].calc_checksum()
                pkt[1].calc_checksum()
                return pkt, True

        elif dst == out_addr:  # Routing into the virtual network.
            if type(pkt[2]) in (UDP, TCP):
                smac, src, sport = pkt.src, pkt[1].src, pkt[2].sport
                name = names[type(pkt[2])]
                rule = rules[name, (src, sport), pkt[2].dport, 2]
                if rule is not None:
                    ip, port = rule[:2]
                    pkt[2].dport = port
                    if (pkt.haslayer(TCP) and pkt[2].flags['F']) or pkt.haslayer(UDP):
                        if rule[-1] != -1:
                            rules[name, (src, sport), pkt[2].dport, 2] = (*rule[:-1], rules.base_ttl)
                    pkt[1].dst = ip
                    pkt.src = mac
                    pkt.dst = routing_table[ip]
                    pkt[2].calc_checksum(pkt[1].src, pkt[1].dst)
                    pkt[1].calc_checksum()
                    return pkt

            elif pkt.haslayer(ICMP):
                smac, src, ptype, seq = pkt.src, pkt[1].src, pkt[2].type, pkt[2].seq
                if ptype in ICMP_TYPES.keys():  # Request / Reply ICMP
                    ptype = ICMP_TYPES[ptype]
                    rule = rules['icmp', (src, ptype, seq)]
                    if rule is not None:
                        rules['icmp', (src, ptype, seq)] = (*rule[:-1], rules.base_ttl)
                        ip = rule[0]
                        pkt[IP].dst = ip
                        pkt.src = mac
                        pkt.dst = routing_table[ip]
                        for i in (2, 1):
                            pkt[i].calc_checksum()
                        return pkt

                else:  # Error Reporting ICMP
                    source_pkt = pkt[3]
                    if source_pkt.haslayer(ICMP):
                        rule = rules['icmp', (source_pkt.dst, source_pkt[1].type, source_pkt[1].seq)]
                        if rule is not None:
                            rules['icmp', (source_pkt.dst, source_pkt[1].type, source_pkt[1].seq)] = (*rule[:-1], rules.base_ttl)
                            ip = rule[0]
                            pkt[1].dst = ip
                            pkt[3].src = ip
                            pkt.src = mac
                            pkt.dst = routing_table[ip]
                            for i in (3, 2, 1):
                                pkt[i].calc_checksum()
                            return pkt

                    elif source_pkt.haslayer(TCP) or source_pkt.haslayer(UDP):
                        name = 'tcp' if pkt.haslayer(TCP) else 'udp'
                        rule = rules[name, (source_pkt.dst, source_pkt.payload.dport), source_pkt.payload.sport, 1]
                        if rule is not None:
                            if rule[-1] != -1:
                                rules[name, (source_pkt.dst, source_pkt.payload.dport), source_pkt.payload.sport, 1] = (*rule[:-1], rules.base_ttl)
                            ip, port = rule[:2]
                            pkt[4].sport = port
                            pkt[3].src = ip
                            pkt[1].dst = ip
                            pkt.src = mac
                            pkt.dst = routing_table[ip]
                            pkt[4].calc_checksum(pkt[3].src, pkt[3].dst)
                            for i in (3, 2, 1):
                                pkt[i].calc_checksum()
                            return pkt
