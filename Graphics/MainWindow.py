from PyQt5 import QtCore, QtWidgets, QtGui
from Graphics.Statistics import Statistics
from Graphics.Screens import MainScreen, ClientsScreen, DHCP_Screen, DNS_Screen, SettingsScreen
from socket import inet_ntoa, inet_aton
from scapy_p0f import p0f
from scapy.layers.inet import IP
import datetime


class MainWindow(QtWidgets.QMainWindow):

    def __init__(self, lease_time, free_ip, addr, mask, mtu, dos_rate, thread_count, min_mtu, max_mtu, db_name,
                 remove_client_func, change_free_ip_func, attack_manager, update_dns, dns_blacklist, router_manager):
        super().__init__()

        self.setWindowTitle('MataNet')
        self.data = Statistics(self.add_log, lease_time)
        self.free_ip = free_ip
        self.mask = mask
        self.addr = addr
        self.mtu = mtu
        self.lease_time = lease_time
        self.dos_rate = dos_rate
        self.thread_count = thread_count
        self.min_mtu = min_mtu
        self.max_mtu = max_mtu
        self.db_name = db_name
        self.remove_client_func = remove_client_func
        self.change_free_ip_func = change_free_ip_func
        self.attack_manager = attack_manager
        self.update_dns = update_dns
        self.dns_blacklist = dns_blacklist
        self.router_manager = router_manager

        self.setCentralWidget(QtWidgets.QFrame())
        self.centralWidget().setLayout(QtWidgets.QHBoxLayout())
        splitter = QtWidgets.QSplitter()
        splitter.setLineWidth(1)
        splitter.setOrientation(QtCore.Qt.Horizontal)
        splitter.setHandleWidth(7)
        splitter.setChildrenCollapsible(False)
        self.centralWidget().layout().addWidget(splitter)

        self.container = QtWidgets.QStackedWidget(self)
        self.container.setLineWidth(3)
        self.container.setFrameShape(QtWidgets.QFrame.Box)
        self.container.setFrameShadow(QtWidgets.QFrame.Plain)
        splitter.addWidget(self.container)

        self.log_frame = QtWidgets.QFrame(splitter)
        self.log_frame.setLineWidth(3)
        self.log_frame.setFrameShape(QtWidgets.QFrame.Box)
        self.log_frame.setFrameShadow(QtWidgets.QFrame.Plain)
        self.log_frame.setMinimumSize(250, 150)
        self.log_frame.setLayout(QtWidgets.QVBoxLayout())
        self.log_frame.layout().setContentsMargins(3, 16, 3, 3)
        log_header = QtWidgets.QLabel()
        log_header.setStyleSheet('margin-bottom: 10px')
        font = QtGui.QFont('Arial', 16)
        font.setBold(True)
        log_header.setFont(font)
        log_header.setText('LOG')
        log_header.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.log_frame.layout().addWidget(log_header)
        self.log = QtWidgets.QListWidget()
        self.log.setWordWrap(True)
        self.log.setTextElideMode(QtCore.Qt.TextElideMode.ElideNone)
        self.log.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.log.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.log.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.log.setStyleSheet('QListWidget {border: 1px solid black}')
        self.log_frame.layout().addWidget(self.log)
        self.log.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        splitter.addWidget(self.log_frame)

        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(0, 3)

        self.current = None
        self.menu_conf()

    def set_screen(self, scr):
        if self.current is not None:
            self.current.setParent(None)
            self.container.removeWidget(self.current)
        self.container.addWidget(scr)
        self.current = scr
        if self.container.isHidden(): self.container.show()
        self.setWindowTitle(f'MataNet - {self.current.NAME}')
        self.data.update.set()

    def add_log(self, data):
        item = QtWidgets.QListWidgetItem(f'[{datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]}] {data}')
        item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEnabled)
        self.log.addItem(item)

    def add_pkt(self, time, pkt, new_comm):
        temp = pkt
        while type(temp.payload) != bytes:
            temp = temp.payload
        name = type(temp).__name__.lower()
        if name != 'ethernet':
            if name == 'tcp' and temp.flags['S'] == '1' and temp.flags['A'] == '0':
                result = p0f(IP(pkt[1].parse()))
                if result is not None: os = result[0][2]
                else: os = ''
            else: os = ''
            self.data.update_pkt((pkt.payload.src if pkt.payload.src in self.data.clients() else pkt.payload.dst),
                                 name, new_comm, os)
        if hasattr(self.current, 'add_pkt') and callable(getattr(self.current, 'add_pkt')):
            self.current.add_pkt(time, pkt)

    def add_client(self, ip, mac, name, new_screen=False):
        if inet_aton(ip) in self.data.clients():
            self.data.client_stats[ip][-1] = self.data.lease_time
            self.add_log(f"'{ip}' has renewed his DHCP lease ({self.data.lease_time}s)")
            return
        if not new_screen:
            self.data.add_client((ip, mac, name))
        if hasattr(self.current, 'add_client') and callable(getattr(self.current, 'add_client')):
            self.current.add_client((ip, mac, name))

    def remove_client(self, ip, forced=False):
        self.data.remove_client(ip)
        if forced:
            self.remove_client_func(ip)
        if hasattr(self.current, 'remove_client') and callable(getattr(self.current, 'remove_client')):
            self.current.remove_client(ip)

    def menu_conf(self):
        menubar = QtWidgets.QMenuBar()
        menubar.addAction('General Data', lambda: self.set_screen(MainScreen.MainScreen(self)))
        menubar.addAction('Settings', lambda: self.set_screen(SettingsScreen.SettingsScreen(self, self.addr, self.mask,
                self.mtu, self.lease_time, self.thread_count, self.dos_rate, self.min_mtu, self.max_mtu, self.db_name,
                self.attack_manager, self.router_manager)))
        menubar.addAction('Clients', lambda: self.set_screen(ClientsScreen.ClientsScreen(self,
                            lambda x: self.attack_manager.add_to_blacklist(x) if not \
                                self.attack_manager.is_in_blacklist(x) else self.attack_manager.remove_from_blacklist(x),
                            self.remove_client)))
        menubar.addAction('DHCP', lambda: self.set_screen(DHCP_Screen.DHCP_Screen(self, self.free_ip, self.mask, self.change_free_ip_func)))
        menubar.addAction('DNS', lambda: self.set_screen(DNS_Screen.DNS_Screen(self, self.update_dns, self.dns_blacklist)))
        self.setMenuBar(menubar)
