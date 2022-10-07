from socket import inet_aton, socket, AF_INET, SOCK_STREAM
import scapy.all as s, pydivert as pd
from DHCP import DHCP
import Client


class Sniffer:

    def __init__(self, addr, mask, mac, out_addr, def_gateway_mac, free_ip, interface, pkt_table, client_table):
        self.addr = addr, inet_aton(addr)
        self.mask = mask
        self.mac = mac
        self.out_addr = out_addr
        self.def_gateway_mac = def_gateway_mac
        self.free_ip = free_ip
        self.interface = interface
        self.DHCP = DHCP(addr, mask, mac, interface)
        self.clients = Client.Clients()
        self.tables = (pkt_table, client_table)

    @staticmethod
    def find_free_port():
        s1 = socket(AF_INET, SOCK_STREAM)
        s1.bind(('', 0))
        port = s1.getsockname()[1]
        # Closing the port later ensures that it won't be used by a different program until a response is received.
        return port, s1

    def dhcp_handler(self, pkt):
        print('DHCP Packet Detected.')
        data = bytes(pkt[s.UDP].payload)
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
            if options[i] == 54:
                if options[i + 2: i + 2 + op_len] != self.addr[1]:
                    self.free_ip.append(self.clients[cli_mac].addr)
                    self.clients -= self.clients[cli_mac]
                    print('DHCP process terminated.')
                    return
                elif mes_type != 7:
                    print('Client added via DHCP.')
            if options[i] == 50:  # Requested IP Address
                ip = options[i + 2: i + 2 + op_len]
            elif options[i] == 12:  # Host Name
                name = options[i + 2: i + 2 + op_len]
            i += op_len + 2

        if mes_type == 1:  # Discover
            self.clients += Client.Client(cli_mac, DHCP.find_ip(ip, self.free_ip))
            self.DHCP.discover(cli_mac, self.clients[cli_mac].addr, transc_id)
        elif mes_type == 3:  # Request
            if self.clients[cli_mac]:
                self.DHCP.request(cli_mac, self.clients[cli_mac].addr, transc_id)
                mac_str = ':'.join(hex(i)[2:].zfill(2) for i in cli_mac)
                ip_str = '.'.join(str(i) for i in self.clients[cli_mac].addr)
                self.tables[1].insert(parent='', index='end', text='', values=(mac_str, ip_str))
                self.tables[1].yview_moveto(1)

        else:  # Release
            if self.clients[cli_mac]:
                for client in self.tables[1].get_children():
                    if self.tables[1].item(client)['values'][0] == ':'.join(hex(i)[2:].zfill(2) for i in cli_mac):
                        self.tables[1].delete(client)
                        break
                self.free_ip.append(self.clients[cli_mac].addr)
                self.clients[cli_mac].sock.close()
                self.clients -= cli_mac
            print('Client removed.')

    def arp_handler(self, pkt):
        if pkt[s.ARP].pdst == self.addr[0]:
            res = s.Ether() / s.ARP(op=2)
            res[s.ARP].pdst = pkt[s.ARP].psrc
            res[s.ARP].hwdst = pkt[s.ARP].hwsrc
            res[s.ARP].psrc = self.addr[0]
            res[s.Ether].dst = pkt[s.Ether].src
            s.sendp(res, iface=self.interface)

    def sniff_rst(self):
        w = pd.WinDivert(filter=f'ip.SrcAddr == {self.out_addr} and tcp and tcp.Rst == 1')
        w.open()
        while True:
            pkt = w.recv()
            if self.clients[pkt.src_port] is None:
                w.send(pkt)

    def sniff_handler(self, pkt):
        smac, src, dmac, dst = \
            pkt[s.Ether].src, pkt[s.IP].src, pkt[s.Ether].dst, pkt[s.IP].dst

        if bin(int(dmac.split(':')[-1][0], 16))[2:].zfill(4)[0] == '1' and dmac == self.mac:  # Unicast

            if dst not in (self.addr[0], self.out_addr):

                if pkt.haslayer(s.TCP) or pkt.haslayer(s.UDP):
                    if self.clients[src] is not None:  # NAT Address
                        port, sock = self.find_free_port()
                        self.clients[src].tcp_communications[port] = (pkt[0][2].sport, sock)
                        pkt[0][2].sport = port
                        pkt[s.IP].src = self.out_addr
                    pkt[s.Ether].src = self.mac
                    pkt[s.Ether].dst = self.def_gateway_mac
                    del pkt[s.IP].chksum
                    del pkt[0][2].chksum

                elif pkt.haslayer(s.ICMP):
                    if self.clients[src] is not None:  # NAT Address
                        self.clients[src].icmp_seq = pkt[s.ICMP].seq
                        pkt[s.IP].src = self.out_addr
                    pkt[s.Ether].src = self.mac
                    pkt[s.Ether].dst = self.def_gateway_mac
                    del pkt[s.IP].chksum
                    del pkt[s.ICMP].chksum

                s.sendp(pkt, iface=self.interface)
                self.tables[0].insert(parent='', index='end', text='', values=[src, pkt[s.IP].dst])
                self.tables[0].yview_moveto(1)

            elif dst == self.out_addr:

                if pkt.haslayer(s.TCP) or pkt.haslayer(s.UDP):
                    if self.clients.get_port(pkt[0][2].dport) is not None:
                        client = self.clients.get_port(pkt[0][2].dport)
                        smac, src = client.mac, client.addr
                        port = pkt[0][2].dport
                        pkt[0][2].dport = client.tcp_communications[port][0]
                        if (pkt.haslayer(s.TCP) and pkt[0][2].flags.F) or pkt.haslayer(s.UDP):
                            client.tcp_communications[port][1].close()
                            del client.tcp_communications[port]
                        pkt[s.IP].dst = src
                        pkt[s.Ether].src = self.mac
                        pkt[s.Ether].dst = smac
                        del pkt[s.IP].chksum
                        del pkt[0][2].chksum

                elif pkt.haslayer(s.ICMP):
                    client = self.clients[pkt[s.ICMP].seq]
                    smac, src = client.mac, client.addr
                    pkt[s.IP].dst = src
                    pkt[s.Ether].src = self.mac
                    pkt[s.Ether].dst = smac
                    del pkt[s.IP].chksum
                    del pkt[s.ICMP].chksum

            s.sendp(pkt, iface=self.interface)
            self.tables[0].insert(parent='', index='end', text='', values=[pkt[s.IP].src, src])
            self.tables[0].yview_moveto(1)
