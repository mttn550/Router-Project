from scapy.interfaces import get_working_if
import scapy.all as s
from socket import gethostbyname, gethostname, inet_aton
from uuid import getnode as get_mac
import threading, sys
from Sniffer import Sniffer
from IGMP import IGMPv3
import tkinter as tk, tkinter.ttk as ttk


ADDR = '10.0.1.1'
MASK = inet_aton('255.255.0.0')
MAC = get_mac().to_bytes(6, 'big').hex(sep=':')
OUT_ADDR = gethostbyname(gethostname())
DEF_GATEWAY_MAC = '0c:b6:d2:e7:e2:c7'
INTERFACE = get_working_if()


if sys.stdout != sys.__stdout__:
    sys.stdout = sys.__stdout__
s.conf.verb = 0

ip_to_int = lambda ip: int(ip.hex(), 16)
free_ip = [inet_aton(ADDR)]

for j in range(1, 5):
    for i in range(2, 256):
        next_ip = free_ip[-1][:4-j] + i.to_bytes(1, 'big') + free_ip[-1][5-j:]
        if ip_to_int(next_ip) & ip_to_int(MASK) != ip_to_int(free_ip[0]) & ip_to_int(MASK):
            break
        free_ip.append(next_ip)
    else:
        continue
    break
free_ip = free_ip[1:]
free_ip.remove((ip_to_int(free_ip[0]) | ~ip_to_int(MASK) & 0xffffffff).to_bytes(4, 'big'))  # Broadcast Address


def table(root, columns):
    frame = tk.Frame(root)

    scroll_x = tk.Scrollbar(frame, orient='horizontal')
    scroll_y = tk.Scrollbar(frame, orient='vertical')
    scroll_y.pack(side='right', fill='y')
    scroll_x.pack(side='bottom', fill='x')

    table = ttk.Treeview(frame, columns=columns, xscrollcommand=scroll_x.set,
                         yscrollcommand=scroll_y.set)
    table.column('#0', width=0, stretch=False)
    table.heading('#0', text='', anchor='center')

    for i in range(len(columns)):
        table.column(columns[i], anchor='center')
        table.heading(columns[i], text=columns[i], anchor='center')

    table.pack()
    scroll_y.config(command=table.yview)
    scroll_x.config(command=table.xview)

    return table, frame


root = tk.Tk()
tk.Label(root, font=('Arial', '18', 'bold'), text='Router up and running!').pack(side='top', pady=10)
pkts = table(root, ['Source', 'Destination'])
pkts[1].pack(side='left', padx=25, pady=40)
clients = table(root, ['MAC', 'IP'])
clients[1].pack(side='left', padx=25, pady=40)


join_pkt = s.Ether(src=MAC) / s.IP(src=OUT_ADDR, dst='224.0.0.9', proto=2) / IGMPv3.join()
s.sendp(join_pkt)


sniffer = Sniffer(ADDR, MASK, MAC, OUT_ADDR, DEF_GATEWAY_MAC, free_ip, INTERFACE, pkts, clients)

dhcp_thread = threading.Thread(target=lambda:
    s.sniff(filter='udp and src port 68 and dst port 67', prn=sniffer.dhcp_handler, iface=INTERFACE), args=())
pkt_thread = threading.Thread(target=lambda: s.sniff(filter='ip', prn=sniffer.sniff_handler, iface=INTERFACE), args=())
rst_thread = threading.Thread(target=sniffer.sniff_rst, args=())
arp_thread = threading.Thread(target=lambda: s.sniff(filter='arp', prn=sniffer.arp_handler, iface=INTERFACE), args=())

dhcp_thread.start()
pkt_thread.start()
arp_thread.start()
rst_thread.start()
root.mainloop()