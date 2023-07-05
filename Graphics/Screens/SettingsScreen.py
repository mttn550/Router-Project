from PyQt5 import QtCore, QtGui, QtWidgets
import json, re, threading
from time import sleep
from socket import inet_aton, inet_ntoa

ip_regex = re.compile(r'^([1-2]?\d{1,2}\.){3}[1-2]?\d{1,2}$')
ip_to_int = lambda ip: int(ip.hex(), 16)


class SettingsScreen(QtWidgets.QScrollArea):

    fields = {'ADDR': ('Router Virtual Address:', lambda x: ip_regex.match(x) and not any(int(i) > 255 for i in x.split('.'))),
              'MASK': ('Subnet Mask:', lambda x: ip_regex.match(x) and not any(int(i) > 255 for i in x.split('.'))
                                                 and re.match(r'^1+(0+)?$', bin(ip_to_int(inet_aton(x)))[2:])),
              'MTU': ('Virtual MTU:', lambda x: x.isdigit()),
              'DHCP_LEASE_TIME': ('DHCP Lease TTL:', lambda x: x.isdigit()),
              'ROUTING_THREAD_COUNT': ('Amount of Routing Threads:', lambda x: x.isdigit()),
              'CRITICAL_DOS_RATE': ('Critical DOS Attack Packet\nRate (Packets per Second):', lambda x: x.isdigit())}
    btn_dict = {}

    def __init__(self, root, addr, mask, mtu, lease_time, thread_count, dos_rate, min_mtu, max_mtu, db_name,
                 attack_manager, router_manager):
        super().__init__()

        self.NAME = 'Settings'
        self.data = root.data
        self.log = root.add_log
        self.min_mtu = min_mtu
        self.max_mtu = max_mtu
        self.attack_manager = attack_manager
        self.router_manager = router_manager
        self.database = f'{db_name}.json'
        self.setWidgetResizable(True)
        self.layout = QtWidgets.QVBoxLayout()

        self.main_frame = QtWidgets.QFrame()
        self.setMinimumSize(810, 300)
        self.main_frame.setMinimumWidth(790)
        self.main_frame.setLayout(self.layout)
        self.setWidget(self.main_frame)
        self.layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        self.layout.setSpacing(10)

        header_font = QtGui.QFont('Arial', 24)
        header_font.setBold(True)
        self.layout.addWidget(QtWidgets.QLabel('Settings', font=header_font))
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        settings_groupbox = QtWidgets.QGroupBox('Settings')
        settings_layout = QtWidgets.QFormLayout()
        settings_groupbox.setLayout(settings_layout)
        settings_groupbox.setLayout(settings_layout)
        data = [addr, mask, mtu, lease_time, thread_count, dos_rate]
        counter = 0
        for field, label in self.fields.items():
            layout = QtWidgets.QHBoxLayout()
            field_widget = QtWidgets.QLineEdit()
            field_widget.setText(str(data[counter]))
            btn = QtWidgets.QPushButton('Update')
            btn.clicked.connect(self.update_settings)
            self.btn_dict[btn] = (field, field_widget, data[counter])
            counter += 1
            layout.addWidget(field_widget)
            layout.addWidget(btn)
            settings_layout.addRow(label[0], layout)
        self.layout.addWidget(settings_groupbox)

        attacks_groupbox = QtWidgets.QGroupBox('Attack Management')
        attacks_layout = QtWidgets.QHBoxLayout()
        attacks_groupbox.setLayout(attacks_layout)

        blacklayout = QtWidgets.QVBoxLayout()
        self.blacklist = QtWidgets.QListWidget()
        for i in self.attack_manager.blacklist:
            self.blacklist.addItem(inet_ntoa(i))
        self.blacklist.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        blacklayout.addWidget(self.blacklist)
        btn_layout = QtWidgets.QHBoxLayout()

        btn1 = QtWidgets.QPushButton('Remove from Blacklist')
        btn1.clicked.connect(lambda: self.update_blacklist(False))
        btn_layout.addWidget(btn1)
        btn2 = QtWidgets.QPushButton('Move to Whitelist')
        btn2.clicked.connect(lambda: self.update_blacklist(True))
        btn_layout.addWidget(btn2)
        blacklayout.addLayout(btn_layout)
        attacks_layout.addLayout(blacklayout)

        whitelayout = QtWidgets.QVBoxLayout()
        self.whitelist = QtWidgets.QListWidget()
        for i in self.attack_manager.whitelist:
            self.whitelist.addItem(inet_ntoa(i))
        self.whitelist.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        whitelayout.addWidget(self.whitelist)
        btn_layout2 = QtWidgets.QHBoxLayout()
        btn3 = QtWidgets.QPushButton('Remove from Whitelist')
        btn3.clicked.connect(lambda: self.update_whitelist(False))
        btn_layout2.addWidget(btn3)
        btn4 = QtWidgets.QPushButton('Move to Blacklist')
        btn4.clicked.connect(lambda: self.update_whitelist(True))
        btn_layout2.addWidget(btn4)
        whitelayout.addLayout(btn_layout2)
        attacks_layout.addLayout(whitelayout)
        self.layout.addWidget(attacks_groupbox)

        bridge_groupbox = QtWidgets.QGroupBox('Virtual Bridging')
        bridge_layout = QtWidgets.QVBoxLayout()
        bridge_groupbox.setLayout(bridge_layout)

        bridge_lists = QtWidgets.QHBoxLayout()

        connected_layout = QtWidgets.QVBoxLayout()
        connected_layout.addWidget(QtWidgets.QLabel('Connected Routers:'))
        self.connected = QtWidgets.QListWidget()
        self.connected.setSelectionMode(QtWidgets.QListWidget.SelectionMode.SingleSelection)
        self.connected.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.connected.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.connected.setMinimumSize(300, 100)
        for i in router_manager.routers:
            self.connected.addItem(i.ip)
            self.connected.item(self.connected.count() - 1).setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.connected.itemSelectionChanged.connect(self.view_router_clients)
        connected_layout.addWidget(self.connected)
        bridge_lists.addLayout(connected_layout)

        clients_layout = QtWidgets.QVBoxLayout()
        clients_layout.addWidget(QtWidgets.QLabel('Connected Clients:'))
        self.router_clients = QtWidgets.QListWidget()
        self.router_clients.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.router_clients.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.router_clients.setMinimumSize(300, 100)
        clients_layout.addWidget(self.router_clients)
        bridge_lists.addLayout(clients_layout)

        bridge_layout.addLayout(bridge_lists)

        remove_btn = QtWidgets.QPushButton('Disconnect from Router')
        remove_btn.clicked.connect(self.disconnect_from_router)
        bridge_layout.addWidget(remove_btn)

        self.add_frame = QtWidgets.QFrame()
        self.add_frame.setFixedWidth(150)
        self.add = QtWidgets.QHBoxLayout(self.add_frame)
        self.ip_add_data = []
        for i in range(4):
            if i != 0:
                self.add.addWidget(QtWidgets.QLabel('.'))
            line_edit = QtWidgets.QLineEdit()
            line_edit.setFixedWidth(30)
            line_edit.setMaxLength(3)
            self.ip_add_data.append(line_edit)
            self.add.addWidget(line_edit)
        self.add.setSpacing(1)
        add_layout = QtWidgets.QHBoxLayout()
        add_layout.addWidget(self.add_frame)
        btn = QtWidgets.QPushButton('Connect to Router')
        btn.clicked.connect(self.connect_to_router)
        add_layout.addWidget(btn)
        bridge_layout.addLayout(add_layout)

        self.layout.addWidget(bridge_groupbox)

        threading.Thread(target=self.add_to_blacklist, daemon=True).start()
        threading.Thread(target=self.update_router_list, daemon=True).start()

    def update_blacklist(self, move):
        ip = self.blacklist.selectedItems()
        if not ip: return
        for addr in ip:
            self.attack_manager.remove_from_blacklist(inet_aton(addr.text()))
            if move:
                self.whitelist.addItem(addr.text())
                self.attack_manager.add_to_whitelist(inet_aton(addr.text()))
            self.blacklist.takeItem(self.blacklist.row(addr))

    def update_whitelist(self, move):
        ip = self.whitelist.selectedItems()
        if not ip: return
        for addr in ip:
            self.attack_manager.remove_from_whitelist(inet_aton(addr.text()))
            if move:
                self.blacklist.addItem(addr.text())
                self.attack_manager.add_to_blacklist(inet_aton(addr.text()))
            self.whitelist.takeItem(self.whitelist.row(addr))

    def update_settings(self):
        key, value, og_value = self.btn_dict[self.sender()]
        value = value.text()
        if self.fields[key][1](value):
            if key == 'MTU' and not self.min_mtu <= int(value) <= self.max_mtu:
                return
            self.log(f'{key} updated to be {value}. (Was {og_value})')
            if type(og_value) == int:
                value = int(value)
            with open(self.database, "r") as jsonFile:
                data = json.load(jsonFile)
            data[key] = value
            with open(self.database, "w") as jsonFile:
                json.dump(data, jsonFile)

    def add_to_blacklist(self):
        while True:
            self.attack_manager.blacklist_changed.wait()
            self.attack_manager.blacklist_changed.clear()
            try:
                self.blacklist.addItem(inet_ntoa(self.attack_manager.blacklist[-1]))
            except RuntimeError:
                return

    def update_router_list(self):
        while True:
            to_add = [i.ip for i in self.router_manager.routers]
            to_remove = []
            try:
                for i in range(self.connected.count()):
                    ip = self.connected.item(i).text()
                    if ip in to_add: to_add.remove(ip)
                    else: to_remove.append(ip)
                for ip in to_remove:
                    for i in range(self.connected.count()):
                        ip1 = self.connected.item(i).text()
                        if ip == ip1:
                            if self.connected.selectedItems() and self.connected.selectedItems()[0] == self.connected.item(i):
                                self.router_clients.clear()
                            self.connected.takeItem(i)
                            break
                for ip in to_add:
                    self.connected.addItem(ip)
                for router in self.router_manager.routers:
                    if router.clients_changed.is_set():
                        print(router.ip)
                        if self.connected.selectedItems(): print(self.connected.selectedItems()[0].text())
                        else: print(None)
                        if self.connected.selectedItems() and router.ip == self.connected.selectedItems()[0].text():
                            clients = router.clients
                            self.router_clients.clear()
                            print('cleared')
                            for client in clients:
                                self.router_clients.addItem(inet_ntoa(client))
                            print('updated')
                        router.clients_changed.clear()
            except RuntimeError:
                print('eror detected')
                break
            sleep(1)

    def view_router_clients(self):
        ip = self.connected.selectedItems()
        if not ip: return
        else: ip = ip[0].text()
        for router in self.router_manager.routers:
            if router.ip == ip:
                clients = router.clients
                self.router_clients.clear()
                for client in clients:
                    self.router_clients.addItem(client)
                break

    def connect_to_router(self):
        if any((not i.text().isdigit()) or int(i.text()) > 255 for i in self.ip_add_data): return
        ip = '.'.join(i.text() for i in self.ip_add_data)
        self.router_manager.contact_router(ip)

    def disconnect_from_router(self):
        ip = self.connected.selectedItems()
        if not ip: return
        else: ip = ip[0].text()
        routers = self.router_manager.routers.copy()
        for router in routers:
            if router.ip == ip:
                router.sock.close()
                self.router_manager.remove_router(router)
                break
