from scapy.layers.inet import Ether, IP, UDP
from socket import inet_aton

BROADCAST = 'ff:ff:ff:ff:ff:ff', '255.255.255.255'


def dhcp_handler(pkt, mac, addr, mask, free_ip, clients):
    data = bytes(pkt[UDP].payload)
    transc_id = data[4:8]
    cli_mac = data[28:34]
    options = data[240:]

    name, ip = None, None
    i = 0

    while i < len(options):
        if options[i] == 255 or (ip is not None and name is not None):
            break
        op_len = options[i + 1]
        if options[i] == 53:
            mes_type = options[i + 2]
        elif options[i] == 54:
            if options[i + 2: i + 2 + op_len] != inet_aton(addr):  # The client refused to accept my offer.
                for client_ip, client_mac in clients.items():
                    if client_mac[0] == cli_mac:
                        free_ip.add(inet_aton(client_ip))
                        del clients[client_ip]
                        break
                return
        elif options[i] == 50:  # Requested IP Address
            ip = options[i + 2: i + 2 + op_len]
        elif options[i] == 12:  # Host Name
            name = options[i + 2: i + 2 + op_len]
        i += op_len + 2

    if mes_type == 1:  # Discover
        ip = find_ip(ip, free_ip)
        clients[ip] = (cli_mac, name)
        return discover(mac, addr, mask, cli_mac, ip, transc_id)
    elif mes_type == 3:  # Request
        for client_ip, client_mac in clients:
            if client_mac[0] == cli_mac:
                return request(mac, addr, mask, cli_mac, client_ip, transc_id)
    else:  # Release
        for client_ip, client_mac in clients.items():
            if client_mac[0] == cli_mac:
                free_ip.add(inet_aton(client_ip))
                del clients[client_ip]


def find_ip(requested_ip, free_ip):
    if requested_ip is not None and requested_ip in free_ip:
        free_ip.remove(requested_ip)
        return requested_ip
    return free_ip.pop()


def discover(mac, addr, mask, cli_mac, ip, transc_id):
    return (Ether(src=mac, dst=BROADCAST[0]) /
            IP(src=addr, dst=BROADCAST[1]) /
            UDP(dport=68, sport=67) /
            offer(addr, mask, transc_id, transc_id, ip, cli_mac))


def offer(addr, mask, transc_id, new_ip, cli_mac, code=b'\x02'):
    data = b'\x02\x01\x06\x00%b' % transc_id + b'\x00' * 8 + new_ip + b'\x00' * 8 + cli_mac + b'\x00' * 202 + \
           b'\x63\x82\x53\x63\x35\x01%b\x36\x04%b\x33\x04\x00\x00\x0e\x10\x01\x04%b\x03\x04%b\x06\x04%b\xff' \
           % (code, inet_aton(addr), mask, inet_aton(addr), inet_aton('10.0.0.138'))
    return data


def request(mac, addr, mask, cli_mac, ip, transc_id):
    return (Ether(src=mac, dst=BROADCAST[0]) /
            IP(src=addr, dst=BROADCAST[1]) /
            UDP(dport=68, sport=67) /
            acknowledge(addr, mask, transc_id, ip, cli_mac))


def acknowledge(addr, mask, transc_id, new_ip, cli_mac):
    return offer(addr, mask, transc_id, new_ip, cli_mac, b'\x05')
