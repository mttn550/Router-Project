from PyQt5 import QtCore, QtWidgets, QtGui
from Graphics.Statistics import Statistics
from socket import inet_ntoa
from scapy_p0f import p0f
from scapy.layers.inet import IP
import datetime


class MainWindow(QtWidgets.QMainWindow):

    def __init__(self, remove_client_func):
        super().__init__()

        self.setWindowTitle('MataNet')
        self.data = Statistics(self.add_log)
        self.remove_client_func = remove_client_func

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
        if self.current is not None: self.container.removeWidget(self.current)
        self.container.addWidget(scr)
        self.current = scr
        if self.container.isHidden(): self.container.show()
        self.setWindowTitle(f'MataNet - {self.current.NAME}')
        self.data.update.set()
        for i in self.data.clients():
            self.add_client(inet_ntoa(i), *self.data.client_stats[inet_ntoa(i)][:2], True)

    def add_log(self, data):
        item = QtWidgets.QListWidgetItem(f'[{datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]}] {data}')
        item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEnabled)
        self.log.addItem(item)

    def add_pkt(self, time, pkt, new_comm):
        temp = pkt
        while type(temp.payload) != bytes:
            temp = temp.payload
        name = type(temp).__name__.lower()
        if name != 'Ethernet':
            if name == 'TCP' and temp.flags['S'] == '1' and temp.flags['A'] == '0':
                os = p0f(IP(pkt[1].parse()))[0][2]
            else: os = ''
            self.data.update_pkt((pkt.payload.src if pkt.payload.src in self.data.clients() else pkt.payload.dst),
                                 name, new_comm, os)
        if hasattr(self.current, 'add_pkt') and callable(getattr(self.current, 'add_pkt')):
            self.current.add_pkt(time, pkt)

    def add_client(self, ip, mac, name, new_screen=False):
        if not new_screen:
            self.data.add_client((ip, mac, name))
        if hasattr(self.current, 'add_client') and callable(getattr(self.current, 'add_client')):
            self.current.add_client((ip, mac, name))

    def remove_client(self, ip):
        self.remove_client_func(ip)
        self.data.remove_client(ip)
        if hasattr(self.current, 'remove_client') and callable(getattr(self.current, 'remove_client')):
            self.current.remove_client(ip)

    def menu_conf(self):
        menubar = QtWidgets.QMenuBar()
        subnet_menu = QtWidgets.QMenu('&Subnet', self)
        subnet_menu.addAction('Configuration')
        subnet_menu.addAction('Clients')
        subnet_menu.addAction('DHCP Management')
        view_menu = QtWidgets.QMenu('&View', self)
        view_menu.addAction('General Data')
        view_menu.addAction('Traffic')
        view_menu.addAction('Routing Rules')
        # view_menu.addAction('Topology')
        view_menu.addAction('Statistics')
        manage_menu = QtWidgets.QMenu('&Management', self)
        manage_menu.addAction('DNS Management')
        manage_menu.addAction('Attack Handling')
        help_menu = QtWidgets.QMenu('&Help', self)
        help_menu.addAction('Help')
        help_menu.addAction('About')
        menubar.addMenu(subnet_menu)
        menubar.addMenu(view_menu)
        menubar.addMenu(manage_menu)
        menubar.addMenu(help_menu)
        self.setMenuBar(menubar)
