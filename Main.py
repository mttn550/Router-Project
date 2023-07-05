from socket import inet_aton
from psutil import net_if_addrs, net_if_stats
from scapy.all import get_working_ifaces
import multiprocessing, wmi, os, json, re
from Routing.Sniffer import Sniffer as RouteSniff
from Services.Sniffer import Sniffer as ServiceSniff
from Routing.RoutingTable import RoutingTable

OUT_ADDR = wmi.WMI().query('select IPAddress from Win32_NetworkAdapterConfiguration where IPEnabled=TRUE')[0].IPAddress[0]
INTERFACE = next(i for i in net_if_addrs().values() for j in i if j.family == 2 and j.address == OUT_ADDR)
MAC = next(i.address for i in INTERFACE if i.family == -1).lower().replace('-', ':')
BYTE_MAC = b''.join((bytes.fromhex(i) for i in MAC.split(':')))
OUT_MASK = next(i.netmask for i in INTERFACE if i.family == 2)
INTERFACE_NAME = next(i for i in get_working_ifaces() if i.ip == OUT_ADDR).network_name
MAX_MTU = net_if_stats()[next(iter(net_if_addrs().keys()))].mtu
MIN_MTU = 500
INIT = ('10.0.0.1', '255.255.0.0')

DATABASE_NAME = 'RouterDB'

if not os.path.isfile(f'{DATABASE_NAME}.json'):
    ADDR, MASK = INIT
    MTU = MAX_MTU
    DHCP_LEASE_TIME = 3600  # Seconds
    DNS_NAME = 'Router.Matan'  # For custom DNS domains
    ROUTING_THREADS_COUNT = 5
    CRITICAL_DOS_RATE = 42

    ip_to_int = lambda ip: int(ip.hex(), 16)
    first_ip = bytes.fromhex(hex(ip_to_int(inet_aton(ADDR)) & ip_to_int(inet_aton(MASK)) + 1)[2:].zfill(8))
    FREE_IP = [first_ip]

    for j in range(1, 5):
        for i in range(1, 256):
            next_ip = FREE_IP[-1][:4 - j] + i.to_bytes(1, 'big') + FREE_IP[-1][5 - j:]
            if ip_to_int(next_ip) & ip_to_int(inet_aton(MASK)) != ip_to_int(FREE_IP[0]) & ip_to_int(inet_aton(MASK)):
                break
            if next_ip not in FREE_IP: FREE_IP.append(next_ip)
        else:
            continue
        break

    FREE_IP.remove(inet_aton(ADDR))
    FREE_IP.remove((ip_to_int(FREE_IP[0]) | ~ip_to_int(inet_aton(MASK)) & 0xffffffff).to_bytes(4, 'big'))  # Broadcast Address

    with open(f'{DATABASE_NAME}.json', 'w') as db:
        json.dump({'ADDR': ADDR,
                   'MASK': MASK,
                   'MTU': MTU,
                   'DHCP_LEASE_TIME': DHCP_LEASE_TIME,
                   'DNS_NAME': DNS_NAME,
                   'ROUTING_THREADS_COUNT': ROUTING_THREADS_COUNT,
                   'CRITICAL_DOS_RATE': CRITICAL_DOS_RATE,
                   'FREE_IP': [int.from_bytes(i, 'big') for i in FREE_IP]}, db)

else:
    with open(f'{DATABASE_NAME}.json', 'r') as db:
        data = json.load(db)
    ADDR = data['ADDR']
    MASK = data['MASK']
    MTU = data['MTU']
    DHCP_LEASE_TIME = data['DHCP_LEASE_TIME']
    DNS_NAME = data['DNS_NAME']
    ROUTING_THREADS_COUNT = data['ROUTING_THREADS_COUNT']
    CRITICAL_DOS_RATE = data['CRITICAL_DOS_RATE']

    FREE_IP = [i.to_bytes(4, 'big') for i in data['FREE_IP']]
    ip_to_int = lambda ip: int(ip.hex(), 16)
    if ip_to_int(FREE_IP[0]) & ip_to_int(inet_aton(MASK)) != ip_to_int(inet_aton(ADDR)) & ip_to_int(inet_aton(MASK)):
        first_ip = bytes.fromhex(hex(ip_to_int(inet_aton(ADDR)) & ip_to_int(inet_aton(MASK)) + 1)[2:].zfill(8))
        FREE_IP = [first_ip]

        for j in range(1, 5):
            for i in range(1, 256):
                next_ip = FREE_IP[-1][:4 - j] + i.to_bytes(1, 'big') + FREE_IP[-1][5 - j:]
                if ip_to_int(next_ip) & ip_to_int(inet_aton(MASK)) != ip_to_int(FREE_IP[0]) & ip_to_int(
                        inet_aton(MASK)):
                    break
                if next_ip not in FREE_IP: FREE_IP.append(next_ip)
            else:
                continue
            break

        FREE_IP.remove(inet_aton(ADDR))
        FREE_IP.remove((ip_to_int(FREE_IP[0]) | ~ip_to_int(inet_aton(MASK)) & 0xffffffff).to_bytes(4, 'big'))  # Broadcast Address
        with open(f'{DATABASE_NAME}.json', 'w') as db:
            json.dump({'ADDR': ADDR,
                       'MASK': MASK,
                       'MTU': MTU,
                       'DHCP_LEASE_TIME': DHCP_LEASE_TIME,
                       'DNS_NAME': DNS_NAME,
                       'ROUTING_THREADS_COUNT': ROUTING_THREADS_COUNT,
                       'CRITICAL_DOS_RATE': CRITICAL_DOS_RATE,
                       'FREE_IP': [int.from_bytes(i, 'big') for i in FREE_IP]}, db)

    if MTU < MIN_MTU:
        MTU = MIN_MTU
    if MTU > MAX_MTU:
        MTU = MAX_MTU


ip_regex = re.compile(r'^([1-2]?\d{1,2}.){3}[1-2]?\d{1,2}$')
if not ip_regex.match(ADDR):
    ADDR = INIT[0]
if not ip_regex.match(MASK):
    MASK = INIT[1]
FREE_IP = set(FREE_IP)
clients = {}  # IP: MAC, name
routing_table = RoutingTable(BYTE_MAC, INTERFACE_NAME, inet_aton(OUT_ADDR), OUT_MASK, clients)

route_sniff = RouteSniff(ADDR, inet_aton(OUT_ADDR), MASK, INTERFACE_NAME, BYTE_MAC, MAC, MTU, MIN_MTU, MAX_MTU,
                         DATABASE_NAME, DHCP_LEASE_TIME, routing_table, clients, FREE_IP, ROUTING_THREADS_COUNT, CRITICAL_DOS_RATE)
service_sniff = ServiceSniff(BYTE_MAC, inet_aton(OUT_ADDR), ADDR, MASK, INTERFACE_NAME, MTU, DHCP_LEASE_TIME,
                             FREE_IP, clients, tuple(routing_table.hosts.items())[-1], DNS_NAME)

semaphore = multiprocessing.Semaphore(1)
def start_services(pipe): service_sniff.start(pipe, semaphore)
route_pipe, service_pipe = multiprocessing.Pipe(True)
services = multiprocessing.Process(target=start_services, args=(service_pipe,))


if __name__ == '__main__':
    print('Booting up...')
    services.start()
    route_pipe.poll(None); route_pipe.recv_bytes()
    route_sniff.start(route_pipe, semaphore, services)
