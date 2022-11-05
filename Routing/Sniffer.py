import scapy.all as s
import threading, time
from Handler import handler
from Rules import Rules


class Sniffer:

    def __init__(self, addr, out_addr, interface, mac, mtu, def_gateway_mac, clients):
        self.addr = addr
        self.out_addr = out_addr
        self.iface = interface
        self.mac = mac
        self.mtu = mtu
        self.def_gateway_mac = def_gateway_mac
        self.clients = clients
        self.rules = Rules()

        self._cycle = 0
        self._pkt = ()
        self._signals = (threading.Event(), threading.Event(), threading.Event())
        self._stop = False

    def start(self):
        s.sniff(filter=f'ether dst {self.mac} and ip', iface=self.iface, prn=self._sort, stop_filter=lambda x: self._stop)
        threading.Thread(target=lambda: self._tick, args=()).start()
        threading.Thread(target=lambda: self._handler, args=(self._signals[0],)).start()
        threading.Thread(target=lambda: self._handler, args=(self._signals[1],)).start()
        threading.Thread(target=lambda: self._handler, args=(self._signals[2],)).start()

    def _sort(self, pkt):
        """
        Better be... Gryffindor!

        :param pkt: The sniffed packet.
        """
        self._pkt = (*self._pkt, pkt)
        self._signals[self._cycle].set()
        self.cycle = (self._cycle + 1) % 3

    def _handler(self, signal):
        signal.wait()
        while not self._stop:
            signal.clear()
            pkt = self._pkt[0]
            self._pkt = self._pkt[1:]
            pkt = handler(pkt, self.addr, self.out_addr, self.mac, self.def_gateway_mac, self.clients, self.rules)
            if pkt is not None:
                s.sendp(pkt.fragment(self.mtu), iface=self.iface)
            signal.wait()

    def _tick(self):
        while not self._stop:
            time.sleep(1)
            self.rules.tick()

    def stop(self):
        self._stop = True
