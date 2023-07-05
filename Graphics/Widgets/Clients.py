from PyQt5 import QtCore, QtGui, QtWidgets
from socket import inet_aton


class MainWindowClient(QtWidgets.QFrame):

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QHBoxLayout(self)
        self.setLayout(layout)
        self.pic = QtWidgets.QLabel()
        self.pic.setMinimumSize(100, 100)
        self.pic.setMaximumSize(100, 100)
        self.pic.setScaledContents(True)
        self.pic.setStyleSheet('margin-bottom:5px')
        layout.addWidget(self.pic)
        frame = QtWidgets.QFrame()
        self.ip = QtWidgets.QLabel(frame)
        self.ip.setMinimumSize(160, 40)
        self.ip.setFont(QtGui.QFont('JetBrains Mono'))
        self.mac = QtWidgets.QLabel(frame)
        self.mac.setMinimumSize(160, 65)
        self.mac.setFont(QtGui.QFont('JetBrains Mono'))
        self.name = QtWidgets.QLabel(frame)
        self.name.setMinimumSize(160, 90)
        self.name.setFont(QtGui.QFont('JetBrains Mono'))
        layout.addWidget(frame)
        self.setMaximumSize(280, 110)
        self.setMinimumSize(280, 110)

    def update_client(self, data):
        self.pic.clear()
        self.pic.setPixmap(QtGui.QPixmap('PC.png'))
        self.ip.setText(f'\n {data[0]}')
        self.mac.setText(f'\n\n {data[1]}')
        self.name.setText(f'\n\n\n {data[2] if len(data[2]) < 18 else data[2][:15] + "..."}')

    def remove_client(self):
        self.pic.clear()
        # self.pic.setMovie(QtGui.QMovie('loading.gif'))
        # self.pic.movie().start()
        self.ip.setText('')
        self.mac.setText('')
        self.name.setText('')

    def is_client(self):
        return not self.ip.text() == ''


class ClientScreenClient(QtWidgets.QFrame):

    def __init__(self, name, ip, mac, os, lease, suspend_func, remove_func, parent=None):
        super().__init__(parent)
        self.name = name
        self.ip = ip
        self.mac = mac
        self.os = os
        self.lease = lease
        self.suspend_func = suspend_func
        self.remove_func = remove_func

        self.name_func = lambda name: (name if len(name) <= 35 else name[:32] + '...')
        self.ip_func = lambda ip: ip
        self.mac_func = lambda mac: mac
        self.os_func = lambda os: os if os else 'Unknown'
        self.lease_func = lambda lease: str(lease) + 's'

        layout = QtWidgets.QHBoxLayout()
        self.setLayout(layout)
        self.data_layout = QtWidgets.QFormLayout()
        self.data_layout.addRow(QtWidgets.QLabel('setting'), QtWidgets.QLabel('data'))
        btn_layout = QtWidgets.QVBoxLayout()
        btn_layout.setContentsMargins(15, 0, 0, 0)

        layout.addLayout(self.data_layout)
        self.translate()

        for i in (('Suspend / Resume Service', lambda: self.suspend_func(inet_aton(self.ip))),
                  ('Remove Client', lambda: self.remove_func(self.ip))):
            btn = QtWidgets.QPushButton(i[0])
            btn.setFixedHeight(50)
            btn.setFont(QtGui.QFont('Arial', 9))
            btn.clicked.connect(i[1])
            btn_layout.addWidget(btn)
        layout.addLayout(btn_layout)

        self.setFrameShape(QtWidgets.QFrame.Shape.Box)
        self.setFixedHeight(200)
        self.setMinimumHeight(200)

    def update_client(self, **kwargs):
        for key, value in kwargs.items():
            self.__setattr__(key, value)
            if eval(f'self.{key}_label.text() != self.{key}_func(self.{key})'):
                eval(f'self.{key}_label.setText(self.{key}_func(self.{key}))')

    def translate(self):
        bold_font = QtGui.QFont('JetBrains Mono', 11)
        bold_font.setBold(True)
        font = QtGui.QFont('JetBrains Mono', 11)
        widgets = set()
        for i in range(self.data_layout.count()):
            widgets.add(self.data_layout.itemAt(i).widget())
        for i in widgets:
            i.setParent(None)
        del widgets

        self.name_label = QtWidgets.QLabel(self.name_func(self.name), font=font)
        self.data_layout.addRow(QtWidgets.QLabel('Name: ', font=bold_font), self.name_label)
        self.ip_label = QtWidgets.QLabel(self.ip, font=font)
        self.data_layout.addRow(QtWidgets.QLabel('IP Address: ', font=bold_font), self.ip_label)
        self.mac_label = QtWidgets.QLabel(self.mac, font=font)
        self.data_layout.addRow(QtWidgets.QLabel('MAC Address: ', font=bold_font), self.mac_label)
        self.os_label = QtWidgets.QLabel(self.os_func(self.os), font=font)
        self.data_layout.addRow(QtWidgets.QLabel('Operating System: ', font=bold_font), self.os_label)
        self.lease_label = QtWidgets.QLabel(self.lease_func(self.lease), font=font)
        self.data_layout.addRow(QtWidgets.QLabel('DHCP Lease Time: ', font=bold_font), self.lease_label)
