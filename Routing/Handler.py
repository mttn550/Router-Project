from scapy.layers.inet import Ether, IP, ICMP, TCP, UDP
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM


ICMP_TYPES = {8: 0, 13: 14, 18: 18, 10: 9}


def find_free_port(type):
    if type == 'tcp':
        s1 = socket(AF_INET, SOCK_STREAM)
    else:
        s1 = socket(AF_INET, SOCK_DGRAM)
    s1.bind(('', 0))
    port = s1.getsockname()[1]
    return port, s1


def handler(pkt, addr, out_addr, mac, def_gateway_mac, clients, rules):
    """
    Shuttle Tydirium, what is your cargo and destination?

    :param pkt: The sniffed packet.
    :param addr: The router's NAT IP address.
    :param out_addr: The computer's IP address.
    :param mac: This computer's MAC address.
    :param def_gateway_mac: The default gateway's MAC address.
    :param clients: The clients' MAC and IP addresses.
    :param rules: The forwarding rules.
    :return: The packet to be routed.
    """

    dmac, dst = pkt[Ether].dst, pkt[IP].dst

    if bin(int(dmac.split(':')[-1][0], 16))[2:].zfill(4)[0] == '1':  # Unicast

        if dst not in (addr, out_addr):  # Routing out of the virtual network.
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                smac, src, sport = pkt[Ether].src, pkt[IP].src, pkt[0][2].sport
                dst, dport = pkt[IP].dst, pkt[TCP].dport
                name = 'tcp' if pkt.haslayer(TCP) else 'udp'
                if src in clients.keys():
                    rule = rules.get_rule(name, src, pkt[TCP].sport)
                    if rule is None:
                        port, sock = find_free_port(name)
                        rules.add4(name, src, dst, sport, dport, sock)
                        pkt[0][2].sport = port
                    else:
                        pkt[0][2].sport = rule[3]
                    pkt[IP].src = out_addr
                pkt[Ether].src = mac
                pkt[Ether].dst = def_gateway_mac
                del pkt[IP].chksum
                del pkt[0][2].chksum
                return pkt

            elif pkt.haslayer(ICMP):
                smac, src, dst, type, seq = pkt[Ether].src, pkt[IP].src, pkt[IP].dst, pkt[ICMP].type, pkt[ICMP].seq
                if src in clients.keys():
                    rules.add('icmp', src, type, seq)
                    pkt[IP].src = out_addr
                pkt[Ether].src = mac
                pkt[Ether].dst = def_gateway_mac
                del pkt[IP].chksum
                del pkt[ICMP].chksum
                return pkt

        elif dst == out_addr:  # Routing into the virtual network.
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                smac, src, sport = pkt[Ether].src, pkt[IP].src, pkt[0][2].sport
                name = 'tcp' if pkt.haslayer(TCP) else 'udp'
                if rules.get_rule(name, (src, sport)) is not None:
                    ip, port = rules.translate(name, (0, 2), (src, sport))
                    pkt[0][2].dport = port
                    if (pkt.haslayer(TCP) and pkt[0][2].flags.F) or pkt.haslayer(UDP):
                        rules.get_rule(name, src, sport).set_tick()
                    pkt[IP].dst = ip
                    pkt[Ether].src = mac
                    pkt[Ether].dst = clients[ip][0]
                    del pkt[IP].chksum
                    del pkt[0][2].chksum
                    return pkt

            elif pkt.haslayer(ICMP):
                smac, src, type, seq = pkt[Ether].src, pkt[IP].src, pkt[ICMP].type, pkt[ICMP].seq
                if type in ICMP_TYPES.keys():  # Request / Reply ICMP
                    type = ICMP_TYPES[type]
                    if rules.get_rule('icmp', (type, seq)):
                        ip = rules.translate('icmp', (0,), (type, seq))
                        pkt[IP].dst = ip
                        pkt[Ether].src = mac
                        pkt[Ether].dst = clients[ip][0]
                        del pkt[IP].chksum
                        del pkt[ICMP].chksum
                        return pkt

                else:  # Error Reporting ICMP
                    source_pkt = pkt[ICMP][1]
                    if source_pkt.haslayer(ICMP):
                        if rules.get_rule('icmp', source_pkt[1].type, source_pkt[1].seq):
                            if rules.get_rule('icmp', (source_pkt[1].type, source_pkt[1].seq)):
                                ip = rules.translate('icmp', (0,), (source_pkt[1].type, source_pkt[1].seq))
                                pkt[IP].dst = ip
                                pkt[ICMP][1].src = ip
                                pkt[Ether].src = mac
                                pkt[Ether].dst = clients[ip][0]
                                for layer in (pkt[IP], pkt[ICMP][0], pkt[ICMP][1]):
                                    del layer.chksum
                                return pkt

                    elif source_pkt.haslayer(TCP) or source_pkt.haslayer(UDP):
                        name = 'tcp' if pkt.haslayer(TCP) else 'udp'
                        if rules.get_rule(name, (source_pkt[0].dst, source_pkt[1].dport)):
                            ip, port = rules.translate(name, (0, 2), (source_pkt[0].dst, source_pkt[1].dport))
                            pkt[ICMP][2].sport = port
                            pkt[ICMP][1].src = ip
                            pkt[IP].dst = ip
                            pkt[Ether].src = mac
                            pkt[Ether].dst = clients[ip][0]
                            for layer in (pkt[IP], pkt[ICMP][0], pkt[ICMP][1], pkt[ICMP][2]):
                                del layer.chksum
                            return pkt
