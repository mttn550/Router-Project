from PyQt5 import QtCore, QtGui, QtWidgets
from socket import inet_ntoa, inet_aton
import re


class DHCP_Screen(QtWidgets.QScrollArea):

    IP_REGEX = re.compile(r'^([1-2]?\d{1,2}.){3}[1-2]?\d{1,2}$')

    def __init__(self, root, free_ip, mask, change_free_ip_func):
        super().__init__()

        self.NAME = 'DHCP'
        self.data = root.data
        self.free_ip = free_ip
        self.mask = mask
        self.ip_to_int = lambda ip: int(ip.hex(), 16)
        self.subnet_addr = self.ip_to_int(next(iter(free_ip))) & self.ip_to_int(inet_aton(mask))
        self.change_free_ip_func = change_free_ip_func

        self.setWidgetResizable(True)
        self.layout = QtWidgets.QFormLayout()

        self.main_frame = QtWidgets.QFrame()
        self.setMinimumSize(640, 300)
        self.main_frame.setMinimumWidth(610)
        self.main_frame.setLayout(self.layout)
        self.setWidget(self.main_frame)
        self.layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        self.layout.setSpacing(10)

        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.in_use = QtWidgets.QListWidget()
        self.in_use.setMinimumSize(200, 50)
        self.in_use.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.in_use.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        in_use_layout = QtWidgets.QVBoxLayout()
        in_use_label = QtWidgets.QLabel('IP Addresses in use:')
        in_use_layout.addWidget(in_use_label)
        self.layout.addRow('IP Addresses in use', self.in_use)

        self.available = QtWidgets.QListWidget()
        self.available.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.available.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.available.setMinimumSize(200, 50)
        self.layout.addRow(QtWidgets.QLabel('Available IP Addresses:'), self.available)
        for i in sorted(free_ip, key=lambda i: int(inet_ntoa(i).split('.')[2]) * 10000 + int(inet_ntoa(i).split('.')[3])):
            self.available.addItem(inet_ntoa(i))
            self.available.item(self.available.count() - 1).setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        remove_btn = QtWidgets.QPushButton('Remove selected IP Address')
        remove_btn.clicked.connect(self.remove_ip)
        self.layout.addWidget(remove_btn)

        self.add_frame = QtWidgets.QFrame()
        self.add_frame.setFixedWidth(150)
        self.add = QtWidgets.QHBoxLayout(self.add_frame)
        self.add.addWidget(QtWidgets.QLabel('.'.join(inet_ntoa(next(iter(free_ip))).split('.')[:mask.count('255')]) + ' '))
        self.ip_add_data = list(inet_ntoa(next(iter(free_ip))).split('.')[:mask.count('255')])

        for i in range(4 - mask.count('255')):
            self.add.addWidget(QtWidgets.QLabel('.'))
            line_edit = QtWidgets.QLineEdit()
            line_edit.setFixedWidth(30)
            line_edit.setMaxLength(3)
            self.ip_add_data.append(line_edit)
            self.add.addWidget(line_edit)

        self.add.setSpacing(1)
        add_layout = QtWidgets.QHBoxLayout()
        add_layout.addWidget(self.add_frame)
        btn = QtWidgets.QPushButton('Add IP')
        btn.setFixedWidth(75)
        btn.clicked.connect(self.add_ip)
        self.add_error_label = QtWidgets.QLabel("\n")
        self.add_error_label.setStyleSheet('color: red')
        add_layout.addWidget(btn)
        add_layout.addWidget(self.add_error_label)
        add_layout.setSpacing(15)
        self.add_error_label.setMinimumWidth(500)
        self.layout.addRow(QtWidgets.QLabel('Add IP:'), add_layout)

        for client in self.data.clients():
            client = inet_ntoa(client)
            self.add_client((client, *self.data.client_stats[client][:2]))

    def add_client(self, data):
        sort_func = lambda i: int(i.split('.')[2]) * 10000 + int(i.split('.')[3])
        if self.in_use.count() == 0:
            self.in_use.addItem(data[0])
            self.in_use.item(0).setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        else:
            for i in range(self.in_use.count()):
                if sort_func(data[0]) < sort_func(self.in_use.item(i).text()):
                    self.in_use.insertItem(i, data[0])
                    self.in_use.item(i).setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
                    break
        for i in range(self.available.count()):
            if self.available.item(i).text() == data[0]:
                self.available.takeItem(i)
                break
        if inet_aton(data[0]) in self.free_ip:
            self.free_ip.remove(inet_aton(data[0]))

    def remove_client(self, ip):
        sort_func = lambda i: int(i.split('.')[2]) * 10000 + int(i.split('.')[3])
        if self.available.count() == 0:
            self.available.addItem(ip)
            self.available.item(0).setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        else:
            for i in range(self.available.count()):
                if sort_func(ip) < sort_func(self.available.item(i).text()):
                    self.available.insertItem(i, ip)
                    self.available.item(i).setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
                    break
        for i in range(self.in_use.count()):
            if self.in_use.item(i).text() == ip:
                self.in_use.takeItem(i)
                break
        if inet_aton(ip) not in self.free_ip:
            self.free_ip.add(inet_aton(ip))

    def add_ip(self):
        ip = '.'.join((i if type(i) is str else i.text() for i in self.ip_add_data))
        if '..' in ip or ip.endswith('.'):
            self.add_error_label.setText('You must fill all empty fields.')
            return
        if not self.IP_REGEX.match(ip) or any(int(i) > 255 for i in ip.split('.')):
            self.add_error_label.setText('The IP address is not\nformatted correctly.')
            return
        if inet_aton(ip) in self.free_ip:
            self.add_error_label.setText('The IP address is\nalready being offered.')
            return
        if inet_aton(ip) in self.data.clients():
            self.add_error_label.setText('The IP address is in active use.')
            return
        self.add_error_label.setText('')
        self.change_free_ip_func(ip)
        self.free_ip.add(inet_aton(ip))
        self.remove_client(ip)

    def remove_ip(self):
        ip = self.available.selectedItems()[0].text()
        if inet_aton(ip) in self.free_ip:
            self.change_free_ip_func(ip)
            self.free_ip.remove(inet_aton(ip))
            for i in range(self.available.count()):
                if self.available.item(i).text() == ip:
                    self.available.takeItem(i)
                    break
