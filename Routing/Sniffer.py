import threading, time, json
from socket import inet_ntoa, inet_aton
from Base import Sniffer as sniffer
from Routing.Handler import handler
from Routing.Rules import Rules
from Routing.RoutingThread import ThreadManager
from Routing.PreventRST import sniff_rst
from Graphics.Main import Graphics
from Graphics.GUI_Thread import GUI_Thread
from .Attacks import AttackHandler


class Sniffer:

    def __init__(self, addr, out_addr, mask, interface, byte_mac, mac, mtu, min_mtu, max_mtu, db_name, lease_time,
                 routing_table, clients, free_ip, thread_count, critical_dos_rate):
        self.SHOW_GUI = True
        self.addr = addr
        self.out_addr = out_addr
        self.iface = interface
        self.byte_mac = byte_mac
        self.mac = mac
        self.routing_table = routing_table
        self.db_name = db_name
        self.clients = clients
        self.rules = Rules()
        self._thread_count = thread_count
        self.graphics = Graphics(mac, addr, mask, mtu, min_mtu, max_mtu, critical_dos_rate, thread_count,
                                 db_name, interface, lease_time, self.stop, self.remove_client, self.change_free_ip,
                                 self.update_dns)
        self.attack_handler = AttackHandler(critical_dos_rate, lambda x: self.graphics.log(x) if self.SHOW_GUI else print(x))
        self.graphics.set_attack_funcs(self.attack_handler)
        self._threads = ThreadManager(self._thread_count, interface, mtu, out_addr,
                                      lambda pkt, router_manager: handler(pkt, self.addr, self.out_addr, mask,
                                                     self.byte_mac, self.routing_table, self.clients,
                                                     self.rules, router_manager), self.clients,
                                      self.graphics.add_pkt, self.SHOW_GUI, self.attack_handler)
        self.graphics.set_router_manager(self._threads.router_manager)
        self._stop = False
        self.free_ip = free_ip

    def start(self, pipe, semaphore, proc):
        self.pipe = pipe
        self.semaphore = semaphore
        self.proc = proc
        client_thread = GUI_Thread(self._update_clients, ())
        client_thread.add_client_signal.connect(self.graphics.add_client)
        client_thread.start()   # Listen for client updates.
        # threading.Thread(target=self._update_clients, daemon=True, args=()).start()
        threading.Thread(target=self._tick, daemon=True, args=()).start()  # Update the rules.
        for i in self._threads.threads: i.start()  # Activate routing threads.
        # Prevent kernel-generated RST packets from being sent:
        threading.Thread(target=lambda: sniff_rst(self.rules), daemon=True).start()
        threading.Thread(target=self._threads.router_manager.accept_routers, daemon=True).start()
        threading.Thread(target=self._threads.router_manager.alert_clients, daemon=True).start()
        sniff = sniffer.Sniffer(filter=f'ether dst {self.mac} and ip', prn=self._sort, iface=self.iface)
        threading.Thread(target=sniff.start, daemon=self.SHOW_GUI).start()  # Start sniffing for packets.
        print('Routing process active!')
        if self.SHOW_GUI: self.graphics.start(self.free_ip)  # Boot up the graphics.

    def _sort(self, time, pkt):
        """
        Better be... Gryffindor!
        :param time: The packet's timestamp.
        :param pkt: The sniffed packet.
        """
        self._threads.add(time, pkt)

    def _tick(self):
        while True:
            time.sleep(1)
            self.rules.tick()
            if self.SHOW_GUI and self.graphics.is_active():
                self.graphics.root.data.tick()

    def _update_clients(self):
        while True:
            if self.pipe.poll(None):
                data = self.pipe.recv_bytes()
                if data[0] == 0x00:
                    if data[1:] in self.clients.keys():
                        del self.clients[data[1:]]
                        if self.SHOW_GUI:
                            self.graphics.remove_client(inet_ntoa(data[1:]))
                            self.graphics.log(f'Client {inet_ntoa(data[1:])} has disconnected.')
                elif data[0] == 0x01:
                    if data[1:5] not in self.clients.keys():
                        self.clients[data[1:5]] = (data[5:11], data[11:].decode())
                        if self.SHOW_GUI:
                            self.graphics.log(f'Client {inet_ntoa(data[1:5])} has connected!')
                    if self.SHOW_GUI:
                        yield inet_ntoa(data[1:5]), ':'.join(hex(i).upper()[2:].zfill(2) for i in data[5:11]), data[11:].decode()
                else:
                    print(data[0])

    def remove_client(self, ip):
        self.semaphore.acquire()
        self.pipe.send_bytes(inet_aton(ip))
        self.semaphore.release()

    def update_dns(self, code, domain, addr):
        self.semaphore.acquire()
        self.pipe.send_bytes(b'DNS' + code + domain + addr)
        self.semaphore.release()

    def change_free_ip(self, ip):
        with open(f'{self.db_name}.json', 'r') as db:
            data = json.load(db)
        ip = inet_aton(ip)
        print(int.from_bytes(ip, 'big') in data['FREE_IP'])
        if ip in self.free_ip: data['FREE_IP'].remove(int.from_bytes(ip, 'big'))
        else: data['FREE_IP'].append(int.from_bytes(ip, 'big'))
        with open(f'{self.db_name}.json', 'w') as db:
            json.dump(data, db)
        self.semaphore.acquire()
        self.pipe.send_bytes(ip)
        self.semaphore.release()

    def stop(self):
        print('Shutting Down...')
        self.proc.terminate()
