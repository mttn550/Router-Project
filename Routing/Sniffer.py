import threading, time
from socket import inet_ntoa, inet_aton
from Base import Sniffer as sniffer
from Routing.Handler import handler
from Routing.Rules import Rules
from Routing.RoutingThread import ThreadManager
from Routing.PreventRST import sniff_rst
from Graphics.Main import Graphics


class Sniffer:

    def __init__(self, addr, out_addr, mask, interface, byte_mac, mac, mtu, routing_table, clients):
        self.SHOW_GUI = True
        self.addr = addr
        self.out_addr = out_addr
        self.iface = interface
        self.byte_mac = byte_mac
        self.mac = mac
        self.routing_table = routing_table
        self.clients = clients
        self.rules = Rules()
        self._thread_count = 3
        self.graphics = Graphics(mac, addr, mask, mtu, interface, self.stop, self.remove_client)
        self._threads = ThreadManager(self._thread_count, interface, mtu, out_addr,
                                      lambda pkt: handler(pkt, self.addr, self.out_addr,
                                                          self.byte_mac, self.routing_table, self.clients, self.rules),
                                      self.graphics.add_pkt)
        self._stop = False

    def start(self, pipe, semaphore, proc):
        self.pipe = pipe
        self.semaphore = semaphore
        self.proc = proc
        threading.Thread(target=self._update_clients, daemon=True, args=()).start()  # Listen for client updates.
        threading.Thread(target=self._tick, daemon=True, args=()).start()  # Update the rules.
        for i in self._threads.threads: i.start()  # Activate routing threads.
        # Prevent kernel-generated RST packets from being sent:
        # threading.Thread(target=lambda: sniff_rst(self.rules), daemon=True).start()
        sniff = sniffer.Sniffer(filter=f'ether dst {self.mac} and ip', prn=self._sort, iface=self.iface)
        threading.Thread(target=sniff.start, daemon=self.SHOW_GUI).start()  # Start sniffing for packets.
        print('Routing process active!')
        if self.SHOW_GUI: self.graphics.start()  # Boot up the graphics.

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
                    self.clients[data[1:5]] = (data[5:11], data[11:].decode())
                    if self.SHOW_GUI:
                        self.graphics.add_client(inet_ntoa(data[1:5]),
                                                 ':'.join(hex(i).upper()[2:].zfill(2) for i in data[5:11]),
                                                 data[11:].decode())
                        self.graphics.log(f'Client {inet_ntoa(data[1:5])} has connected!')
                else:
                    print(data[0])

    def remove_client(self, ip):
        self.semaphore.acquire()
        self.pipe.send_bytes(inet_aton(ip))
        self.semaphore.release()

    def stop(self):
        print('Shutting Down...')
        self.proc.terminate()
