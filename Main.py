from scapy.interfaces import get_working_if
import scapy.all as s
from socket import gethostbyname, gethostname, inet_aton
from uuid import getnode as get_mac
from psutil import net_if_stats
import threading, sys
from Sniffer import Sniffer
from GUI import GUI


ADDR = '10.0.1.1'
MASK = inet_aton('255.255.0.0')
MAC = get_mac().to_bytes(6, 'big').hex(sep=':')
OUT_ADDR = gethostbyname(gethostname())
DEF_GATEWAY_MAC = '0c:b6:d2:e7:e2:c7'
INTERFACE = get_working_if()
<<<<<<< Updated upstream
=======
MTU = net_if_stats()[INTERFACE.name].mtu - 100
>>>>>>> Stashed changes


if sys.stdout != sys.__stdout__:
    sys.stdout = sys.__stdout__
s.conf.verb = 0

ip_to_int = lambda ip: int(ip.hex(), 16)
free_ip = [inet_aton('10.0.0.1')]

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

table_data = ([], [])
sniffer = Sniffer(ADDR, MASK, MAC, OUT_ADDR, DEF_GATEWAY_MAC, free_ip, INTERFACE, MTU, table_data)
# gui = GUI(table_data)

dhcp_thread = threading.Thread(target=lambda:
    s.sniff(filter='udp and src port 68 and dst port 67', prn=sniffer.dhcp_handler, iface=INTERFACE), args=())

pkt_thread = threading.Thread(target=lambda: s.sniff(filter='ip', prn=sniffer.sniff_handler, iface=INTERFACE), args=())

rst_thread = threading.Thread(target=sniffer.sniff_rst, args=())

arp_thread = threading.Thread(target=lambda: s.sniff(filter='arp', prn=sniffer.arp_handler, iface=INTERFACE), args=())

# gui_thread = threading.Thread(target=gui.update_tables, args=())

dhcp_thread.start()
pkt_thread.start()
arp_thread.start()
rst_thread.start()
<<<<<<< Updated upstream
root.mainloop()
=======
# gui_thread.start()
# gui.start()

print('Router up and running!')
>>>>>>> Stashed changes
