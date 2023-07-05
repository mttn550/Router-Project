from Base.Packet import ARP, IP, UDP, TCP, ICMP
from socket import inet_ntoa, inet_aton
from time import time as now, sleep
from threading import Thread, Event
from PyQt5 import QtCore, QtGui, QtWidgets


FLAG_NAMES = {'S': 'SYN', 'U': 'URG', 'A': 'ACK', 'P': 'PSH', 'R': 'RST', 'F': 'FIN', 'N': 'ECN-N', 'E': 'ECN-E', 'CWR': 'CWR'}
ORDER = ('URG', 'SYN', 'FIN', 'PSH', 'ACK', 'RST', 'CWR', 'ECN-N', 'ECN-E')
COLUMNS = ('Delta Time', 'Source', 'Destination', 'Protocol', 'Length', 'Data')
mac_to_str = lambda mac: ':'.join(hex(i).upper()[2:].zfill(2) for i in mac)


class TableManager(QtWidgets.QTabWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.clients = [(None, None, SniffTable())]
        self.addTab(self.clients[0][-1], 'All Packets')
        self.data = []
        self.update_event = Event()
        Thread(target=self.update_tables, args=(), daemon=True).start()

    def add_client(self, ip, mac):
        table = SniffTable()
        self.addTab(table, inet_ntoa(ip))
        self.clients.append((ip, mac, table))

    def remove_client(self, ip):
        for client in self.clients:
            if client[0] == ip:
                client[-1].setParent(None)
                self.removeTab(self.clients.index(client))
                self.clients.remove(client)

    def add(self, time, pkt):
        self.data.append((time, pkt))
        self.update_event.set()

    def update_tables(self):
        while True:
            self.update_event.wait()
            time, pkt = self.data.pop(0)
            for ip, mac, table in self.clients:
                try:
                    if ip is None:
                        table.add(time, pkt)
                    elif pkt.haslayer(IP):
                        if ip in (pkt[1].src, pkt[1].dst):
                            table.add(time, pkt)
                    elif mac in (pkt.src, pkt.dst):
                        table.add(time, pkt)
                except RuntimeError:
                    break
            if not self.data:
                self.update_event.clear()


class SniffTable(QtWidgets.QTableWidget):

    def __init__(self, parent=None):
        super().__init__(0, len(COLUMNS), parent)
        self.setHorizontalHeaderLabels(COLUMNS)
        self.setSelectionMode(QtWidgets.QTableWidget.SelectionMode.SingleSelection)
        self.setSelectionBehavior(QtWidgets.QTableWidget.SelectionBehavior.SelectRows)
        self.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.horizontalHeader().setDefaultSectionSize(100)
        self.horizontalHeader().setMinimumSectionSize(70)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setVisible(False)
        item = QtWidgets.QTableWidgetItem()
        item.setFlags(QtCore.Qt.ItemFlag.ItemIsEnabled | QtCore.Qt.ItemFlag.ItemIsSelectable)
        item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
        self.setItemPrototype(item)
        self.last_time = None
        self.start_time = now()
        self.count = 1

    @staticmethod
    def describe_pkt(pkt):
        if type(pkt) == bytes:
            return 'Unknown'
        if type(pkt.payload) == ARP:
            pkt1 = pkt.payload
            if pkt1.code == 1:
                if pkt1.src == pkt1.dst:
                    return f'I am {inet_ntoa(pkt1.src)}! (ARP Announcement)'
                if pkt1.src == b'\x00\x00\x00\x00':
                    return f'Who has {inet_ntoa(pkt1.dst)}? Tell {pkt1.smac}. (Probe ARP)'
                return f'Who has {inet_ntoa(pkt1.dst)}? Tell {mac_to_str(pkt1.smac)}.'
            if pkt1.code == 2:
                if pkt1.src == pkt1.dst:
                    return f'I am {inet_ntoa(pkt1.src)}! (Gratuitous ARP)'
                return f'{inet_ntoa(pkt1.src)} is at {mac_to_str(pkt1.smac)}.'
        elif type(pkt.payload) == IP:
            pkt1 = pkt.payload
            if type(pkt1.payload) == TCP:
                pkt2 = pkt1.payload
                flags = [FLAG_NAMES[flag] for flag, val in pkt2.flags.items() if val == '1']
                data = '[' + ' '.join(sorted(flags, key=lambda x: ORDER.index(x))) + '] '
                data += f'{pkt2.sport} → {pkt2.dport} '
                data += f'Seq={int.from_bytes(pkt2.seq, "big")} Ack={int.from_bytes(pkt2.ack, "big")}'
                return data
            elif type(pkt1.payload) == UDP:
                pkt2 = pkt1.payload
                data = f'{pkt2.sport} → {pkt2.dport}'
                return data
            elif type(pkt1.payload) == ICMP:
                return 'ICMP'
        return 'Ethernet data'

    def add(self, time, pkt):
        if self.last_time is None:
            self.last_time = time
        if pkt.haslayer(IP):
            src, dst = inet_ntoa(pkt[1].src), inet_ntoa(pkt[1].dst)
        else:
            src, dst = mac_to_str(pkt.src), mac_to_str(pkt.dst)
        temp = pkt
        while type(temp.payload) != bytes:
            temp = temp.payload
        round_time = lambda x: 0.0 if x < 10 ** -4 else round(x, 5)
        data = (round_time(time - self.last_time), src, dst,
                type(temp).__name__, len(pkt.parse()), self.describe_pkt(pkt))
        self.insertRow(self.rowCount())
        for i in range(len(data)):
            self.setItem(self.count - 1, i, QtWidgets.QTableWidgetItem(str(data[i])))
        if self.count == 5000:
            self.removeRow(0)
        else:
            self.count += 1
        self.last_time = time
        self.scrollToBottom()
        sleep(0.06)
