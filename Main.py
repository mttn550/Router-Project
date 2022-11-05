import scapy.all as s
from socket import gethostbyname, gethostname, inet_aton, inet_ntoa
from uuid import getnode as get_mac
from psutil import net_if_stats
import sys, multiprocessing
from Routing.Sniffer import Sniffer as RouteSniff
from Services.Sniffer import Sniffer as ServiceSniff

if sys.stdout != sys.__stdout__:
    sys.stdout = sys.__stdout__
s.conf.verb = 0

ADDR = '10.0.1.1'
MASK = inet_aton('255.255.0.0')
MAC = get_mac().to_bytes(6, 'big').hex(sep=':')
INTERFACE = next(i for i in s.get_working_ifaces() if i.mac == MAC)
OUT_ADDR = INTERFACE.ip
MTU = net_if_stats()[INTERFACE.name].mtu - 100
DEF_GATEWAY_MAC = '0c:b6:d2:e7:e2:c7'

ip_to_int = lambda ip: int(ip.hex(), 16)
first_ip = bytes.fromhex(hex(ip_to_int(ADDR) & ip_to_int(MASK) + 1)[2:].zfill(8))
free_ip = [first_ip]

for j in range(1, 5):
    for i in range(1, 256):
        next_ip = free_ip[-1][:4-j] + i.to_bytes(1, 'big') + free_ip[-1][5-j:]
        if ip_to_int(next_ip) & ip_to_int(MASK) != ip_to_int(free_ip[0]) & ip_to_int(MASK):
            break
        if next_ip not in free_ip: free_ip.append(next_ip)
    else:
        continue
    break

free_ip = free_ip[1:]
free_ip.remove((ip_to_int(free_ip[0]) | ~ip_to_int(MASK) & 0xffffffff).to_bytes(4, 'big'))  # Broadcast Address
free_ip = set(free_ip)

clients = {}  # IP: MAC, name

route_sniff = RouteSniff(ADDR, OUT_ADDR, INTERFACE, MAC, MTU, DEF_GATEWAY_MAC, clients)
route = multiprocessing.Process(target=route_sniff.start, args=())

service_sniff = ServiceSniff(MAC, ADDR, MASK, INTERFACE, MTU, free_ip, clients)
services = multiprocessing.Process(target=service_sniff.start, args=())

route.start()
services.start()
print('Router up and running!')
