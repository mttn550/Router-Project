import copy

from Base.Packet import Ethernet, IP, TCP, UDP, ICMP
from Base.Sniffer import Sniffer
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from Routing import Rules
from socket import inet_aton, inet_ntoa
from threading import Lock
from time import strftime, gmtime
from os import getcwd


ICMP_TYPES = {0: 8, 14: 13, 18: 18, 9: 10}
IP_TO_INT = lambda ip: int(ip.hex(), 16)


def find_free_port(type):
    if type == 'tcp':
        s1 = socket(AF_INET, SOCK_STREAM)
    else:
        s1 = socket(AF_INET, SOCK_DGRAM)
    s1.bind(('', 0))
    port = s1.getsockname()[1]
    return port, s1


with open(getcwd() + r'\Routing\ErrorPage.html', 'r') as file:
    HTML_CONTENT = file.read()


def handler(pkt, addr, out_addr, mask, mac, routing_table, clients, rules:Rules, router_manager):
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

    if type(pkt[1]) == bytes: return
    dmac, dst, src = pkt.dst, pkt[1].dst, pkt[1].src
    names = {TCP: 'tcp', UDP: 'udp', ICMP: 'icmp'}

    if not pkt.ig_bit():  # Unicast

        if dst in router_manager.all_clients().keys():
            pkt[1].ttl -= 1
            router_manager.all_clients()[dst].messages.append(b'\x11\x11\x11\x11' + pkt.parse())
            return

        elif src in router_manager.all_clients().keys():
            pkt[1].ttl -= 1
            pkt.src = mac
            route_mac = routing_table[dst]
            if route_mac is None: return
            pkt.dst = route_mac
            if type(pkt[2]) in (UDP, TCP):
                pkt[2].calc_checksum(pkt[1].src, pkt[1].dst)
            elif pkt.haslayer(ICMP):
                pkt[2].calc_checksum()
            pkt[1].calc_checksum()
            return pkt

        elif dst not in (inet_aton(addr), out_addr):  # Routing out of the virtual network.

            if type(pkt[2]) in (UDP, TCP):
                smac, src, sport = pkt.src, pkt[1].src, pkt[2].sport
                dst, dport = pkt[1].dst, pkt[2].dport
                name = names[type(pkt[1].payload)]
                new = False
                if src in clients.keys() or (IP_TO_INT(src) & IP_TO_INT(inet_aton(mask))) != IP_TO_INT(inet_aton(addr)) & IP_TO_INT(inet_aton(mask)):
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
                            try:
                                pkt[2].sport = rule[-2].getsockname()[1]
                            except OSError: return None
                    pkt[1].src = out_addr
                pkt.src = mac
                route_mac = routing_table[dst]
                if route_mac is None: return None
                pkt.dst = route_mac
                pkt[1].ttl -= 1
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
                pkt[1].ttl -= 1
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
                    pkt[1].ttl -= 1
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
                        pkt[1].ttl -= 1
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
                            pkt[1].ttl -= 1
                            for i in (4, 3, 2, 1):
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
                            pkt[1].ttl -= 1
                            pkt[3].len = len(pkt[3].parse())
                            pkt[4].calc_checksum(pkt[3].src, pkt[3].dst)
                            for i in (3, 2, 1):
                                pkt[i].calc_checksum()
                            return pkt

        elif dst == inet_aton(addr) and type(pkt[2]) == TCP and pkt[2].dport == 80:
            if pkt[2].flags['S'] == '1':  # SYN
                pkt[2].window = b'\xff\xff'
                pkt[2].flags['A'] = '1'
                pkt[2].dport, pkt[2].sport = pkt[2].sport, pkt[2].dport
                pkt[2].ack, pkt[2].seq = (int.from_bytes(pkt[2].seq, 'big') + 1).to_bytes(4, 'big'), b'\x11\x22\x33\x44'
                pkt[1].src, pkt[1].dst = pkt[1].dst, pkt[1].src
                pkt.src, pkt.dst = pkt.dst, pkt.src
                pkt[1].ttl -= 1
                pkt[2].calc_checksum(pkt[1].src, pkt[1].dst)
                pkt[1].calc_checksum()
                return pkt
            elif len(pkt.parse()) != 54 and pkt[2].flags['R'] == '0':  # Request
                # Response Packet:
                http_response = bytes.fromhex('485454502f312e3120323030204f4b0d0a')
                http_response += b'MataNet DNS Blocking Service\x0d\x0aDate: '
                http_response += strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime()).encode()
                http_response += bytes.fromhex('0d0a436f6e74656e742d747970653a20746578742f68746d6c0d0a0d0a')
                http_response += HTML_CONTENT.encode()
                pkt[2].payload = http_response
                pkt[2].window = b'\xff\xff'
                pkt[2].flags['P'] = '0'
                pkt[2].sport, pkt[2].dport = pkt[2].dport, pkt[2].sport
                pkt[2].seq, pkt[2].ack = pkt[2].ack, pkt[2].seq
                pkt[1].src, pkt[1].dst = pkt[1].dst, pkt[1].src
                pkt.src, pkt.dst = pkt.dst, pkt.src
                pkt[1].len = len(pkt[1].parse())
                pkt[1].ttl -= 1
                pkt = Sniffer.construct_packet(pkt.parse())
                pkt[2].calc_checksum(pkt[1].src, pkt[1].dst)
                pkt[1].calc_checksum()

                # FIN Packet:
                pkt1 = copy.deepcopy(pkt)
                pkt1[2].payload = b'\x00' * 6
                pkt1[2].seq = (int.from_bytes(pkt[2].seq, 'big') + len(pkt[2].payload)).to_bytes(4, 'big')
                pkt1[1].len = len(pkt1[1].parse())
                pkt1[1].ttl = 128
                pkt1[2].flags['F'] = '1'
                pkt1 = Sniffer.construct_packet(pkt1.parse())
                pkt1[2].calc_checksum(pkt[1].src, pkt[1].dst)
                pkt1[1].calc_checksum()

                return [pkt, pkt1]
