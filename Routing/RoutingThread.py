from .RouterManager import RouterManager
import threading, pcap, copy
from time import time as now


class ThreadManager:

    def __init__(self, thread_count, interface, mtu, addr, handler, clients, gui_add, show_gui, attack_handler):
        self.gui_add = gui_add
        self.show_gui = show_gui
        self.addr = addr
        self.handler = handler
        self._threads = []
        self.packets = []
        self.thread_count = thread_count
        self.attack_handler = attack_handler
        self.router_manager = RouterManager(clients, lambda x: self.add(now(), x))
        for i in range(thread_count):
            self._threads.append(
                RoutingThread(pcap.pcap(name=interface, immediate=True), self.packets, mtu))
        self.threads = tuple(self._threads)
        self.id = 0

    def add(self, time, packet):
        if self.attack_handler.handler(time, packet):
            return
        pkt = copy.deepcopy(packet)
        pkt = self.handler(pkt, self.router_manager)
        if pkt is not None:
            if self.show_gui:
                if type(pkt) == tuple: pkt, new = pkt
                else: new = False
                if self.addr == packet.payload.dst: self.gui_add(time, pkt, new)
                else: self.gui_add(time, packet, new)
            elif type(pkt) == tuple: pkt, _ = pkt
            if type(pkt) == list:
                for i in pkt:
                    self.packets.append(i)
                    self.threads[self.id].set()
                    self.id = (self.id + 1) % self.thread_count
            else:
                self.packets.append(pkt)
                self.threads[self.id].set()
                self.id = (self.id + 1) % self.thread_count


class RoutingThread(threading.Thread):

    def __init__(self, pcap, packets, mtu):
        super().__init__(daemon=True)
        self.pcap = pcap
        self.packets = packets
        self.signal = threading.Event()
        self.count = 0
        self.stop = False
        self.mtu = mtu

    def set(self):
        self.count += 1
        self.signal.set()

    def run(self):
        self.signal.wait()
        while True:
            if not self.packets: pkt = None
            else: pkt = self.packets.pop(0)
            if pkt is not None:
                if pkt.payload.len <= self.mtu:
                    self.pcap.sendpacket(pkt.parse())
                else:
                    for i in pkt.fragment(self.mtu):
                        self.pcap.sendpacket(i)
            self.count -= 1
            if self.count == 0:
                self.signal.clear()
                self.signal.wait()
