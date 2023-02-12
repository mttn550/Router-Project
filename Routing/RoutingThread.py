import threading, pcap, copy


class ThreadManager:

    def __init__(self, thread_count, interface, mtu, addr, handler, gui_add):
        self.gui_add = gui_add
        self.addr = addr
        self.handler = handler
        self._threads = []
        self.packets = []
        self.thread_count = thread_count
        for i in range(thread_count):
            self._threads.append(
                RoutingThread(pcap.pcap(name=interface, immediate=True), self.packets, mtu))
        self.threads = tuple(self._threads)
        self.id = 0

    def add(self, time, packet):
        pkt = copy.deepcopy(packet)
        pkt = self.handler(pkt)
        if pkt is not None:
            if type(pkt) == tuple: pkt, new = pkt
            else: new = False
            if self.addr == packet.payload.dst: self.gui_add(time, pkt, new)
            else: self.gui_add(time, packet, new)
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
            pkt = self.packets.pop(0)
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
