import pydivert as pd
from socket import inet_aton


def sniff_rst(rules):
    w = pd.WinDivert(filter=f'outbound and tcp and tcp.Rst == 1')
    w.open()
    while True:
        pkt = w.recv()
        if rules['tcp', (inet_aton(pkt.dst_addr), pkt.dst_port), pkt.src_port, 2] is None:
            w.send(pkt)
