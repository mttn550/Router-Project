from Base.Packet import Ethernet, IP, UDP
from socket import inet_aton, inet_ntoa
#from scapy_p0f import p0f
from scapy.layers.inet import Ether


BROADCAST = b'\xff\xff\xff\xff\xff\xff'


def dhcp_handler(pkt, mac, addr, mask, free_ip, clients, mtu, pipe, semaphore):
    """
    Henceforth you shall be known as Darth... Vader.

    :param pkt: The DHCP packet.
    :param mac: My MAC address.
    :param addr: The virtual router's IP address.
    :param mask: The virtual subnet mask.
    :param free_ip: A set of free IP addresses.
    :param clients: A dictionary of the virtual router's clients.
    :param pipe: A connection object to inform the routing process of new clients to be routed.
    """

    data = pkt[2].payload
    transc_id = data[4:8]
    cli_mac = data[28:34]
    options = data[240:]
    name, ip = None, None
    i = 0

    if cli_mac not in (b'\x70\x85\xc2\x3f\x7f\xba', b'\x00\x0c\x29\xea\xba\xbe'): return

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
                        print('DHCP Refused.')
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
        for cli_ip, cli_data in clients.items():
            if cli_data[0] == cli_mac and cli_data[-1]:
                free_ip.add(inet_aton(cli_ip))
                semaphore.acquire()
                pipe.send_bytes(b'\x00' + inet_aton(cli_ip))
                semaphore.release()
                del clients[cli_ip]
                return
        ip = find_ip(ip, free_ip)
        clients[inet_ntoa(ip)] = (cli_mac, name.decode(), -1, False)
        print('Sent IP!')
        return pkt(mac, addr, offer(addr, inet_aton(mask), transc_id, ip, cli_mac, mtu))
    elif mes_type == 3:  # Request
        # Request with discovery:
        for client_ip, client_mac in clients.items():
            if client_mac[0] == cli_mac:
                if client_mac[-1]:  # Removing client:
                    return pkt(mac, addr, nak(addr, inet_aton(mask), transc_id, inet_aton(client_ip), cli_mac, mtu),
                               dst=(client_mac[0], inet_aton(client_ip)))
                if client_mac[2] == -1:
                    print(f'{client_ip} has just connected!')
                    semaphore.acquire()
                    pipe.send_bytes(b'\x01' + inet_aton(client_ip) + client_mac[0] + client_mac[1].encode())
                    semaphore.release()
                clients[client_ip] = (*client_mac[:-1], 3600, False)
                return pkt(mac, addr, acknowledge(addr, inet_aton(mask), transc_id, inet_aton(client_ip), cli_mac, mtu))
        # Request without discovery:
        ip = find_ip(ip, free_ip)
        clients[inet_ntoa(ip)] = (cli_mac, name.decode(), 3600, False)
        print(f'{ip} has just connected!')
        semaphore.acquire()
        pipe.send_bytes(b'\x01' + inet_aton(ip) + cli_mac + name)
        semaphore.release()
        return pkt(mac, addr, acknowledge(addr, inet_aton(mask), transc_id, inet_aton(ip), cli_mac, mtu))
    else:  # Release
        for client_ip, client_mac in clients.items():
            if client_mac[0] == cli_mac:
                print(f'{client_ip} has disconnected.')
                free_ip.add(inet_aton(client_ip))
                semaphore.acquire()
                pipe.send_bytes(b'\x00' + inet_aton(client_ip))
                semaphore.release()
                del clients[client_ip]
                return


def find_ip(requested_ip, free_ip):
    if requested_ip is not None and requested_ip in free_ip:
        free_ip.remove(requested_ip)
        return requested_ip
    return free_ip.pop()


def pkt(mac, addr, data, dst=(BROADCAST, b'\xff\xff\xff\xff')):
    return Ethernet((mac, dst[0], b'\x08\x00',
                     IP({'src': inet_aton(addr), 'dst': dst[1], 'proto': 17, 'payload':
                         UDP(data={'sport': 67, 'dport': 68, 'payload': data})})))


def offer(addr, mask, transc_id, new_ip, cli_mac, mtu, code=b'\x02'):
    data = b'\x02\x01\x06\x00%b' % transc_id + b'\x00\x00\x80' + b'\x00' * 5 + \
           new_ip + b'\x00' * 8 + cli_mac + b'\x00' * 202 + \
           b'\x63\x82\x53\x63\x35\x01%b\x36\x04%b\x33\x04\x00\x00\x0e\x10\x01\x04%b\x03\x04%b\x06\x04%b\x0f\x04\x48' \
           b'\x6f\x6d\x65\x1a\x02%b\xff' \
           % (code, inet_aton(addr), mask, inet_aton(addr), inet_aton('10.0.0.138'), mtu.to_bytes(2, 'big'))
    return data


def acknowledge(addr, mask, transc_id, new_ip, cli_mac, mtu):
    return offer(addr, mask, transc_id, new_ip, cli_mac, mtu, b'\x05')


def force_renew(addr, mask, transc_id, ip, cli_mac, mtu):
    return offer(addr, mask, transc_id, ip, cli_mac, mtu, b'\x09')


def nak(addr, mask, transc_id, ip, cli_mac, mtu):
    return offer(addr, mask, transc_id, ip, cli_mac, mtu, b'\x06')
