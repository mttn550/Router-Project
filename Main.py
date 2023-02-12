from socket import inet_aton
from psutil import net_if_addrs, net_if_stats
from scapy.all import get_working_ifaces
import multiprocessing, wmi
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

ADDR = '192.168.0.1'
MASK = '255.255.0.0'
MTU = MAX_MTU

ip_to_int = lambda ip: int(ip.hex(), 16)
first_ip = bytes.fromhex(hex(ip_to_int(inet_aton(ADDR)) & ip_to_int(inet_aton(MASK)) + 1)[2:].zfill(8))
free_ip = [first_ip]

for j in range(1, 5):
    for i in range(1, 256):
        next_ip = free_ip[-1][:4-j] + i.to_bytes(1, 'big') + free_ip[-1][5-j:]
        if ip_to_int(next_ip) & ip_to_int(inet_aton(MASK)) != ip_to_int(free_ip[0]) & ip_to_int(inet_aton(MASK)):
            break
        if next_ip not in free_ip: free_ip.append(next_ip)
    else:
        continue
    break

free_ip = free_ip[1:]
free_ip.remove((ip_to_int(free_ip[0]) | ~ip_to_int(inet_aton(MASK)) & 0xffffffff).to_bytes(4, 'big'))  # Broadcast Address
free_ip = set(free_ip)

clients = {}  # IP: MAC, name
routing_table = RoutingTable(BYTE_MAC, INTERFACE_NAME, inet_aton(OUT_ADDR), OUT_MASK, clients)

route_sniff = RouteSniff(ADDR, inet_aton(OUT_ADDR), MASK, INTERFACE_NAME, BYTE_MAC, MAC, MTU, routing_table, clients)
service_sniff = ServiceSniff(BYTE_MAC, inet_aton(OUT_ADDR), ADDR, MASK, INTERFACE_NAME, MTU, free_ip, clients,
                             next(iter(routing_table.hosts.items())))

semaphore = multiprocessing.Semaphore(1)
def start_services(pipe): service_sniff.start(pipe, semaphore)
route_pipe, service_pipe = multiprocessing.Pipe(True)
services = multiprocessing.Process(target=start_services, args=(service_pipe,))


if __name__ == '__main__':
    print('Booting up...')
    services.start()
    route_pipe.poll(None); route_pipe.recv_bytes()
    route_sniff.start(route_pipe, semaphore, services)
