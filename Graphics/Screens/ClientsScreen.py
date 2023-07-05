from PyQt5 import QtCore, QtGui, QtWidgets
from ..Widgets.Clients import ClientScreenClient
from socket import inet_ntoa, inet_aton
from threading import Thread


class ClientsScreen(QtWidgets.QScrollArea):

    def __init__(self, root, suspend_client_func, remove_client_func):
        super().__init__()

        self.NAME = 'Clients'
        self.data = root.data
        self.suspend_client_func = suspend_client_func
        self.remove_client_func = remove_client_func
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
        self.layout.addWidget(QtWidgets.QLabel('Clients', font=header_font))

        for client in self.data.clients():
            client = inet_ntoa(client)
            self.add_client((client, *self.data.client_stats[client][:2]))

        # self.remove_client_func = remove_client_func

        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        Thread(target=self.update_clients, daemon=True).start()

    def add_client(self, data):
        ip, mac, name = data
        os = self.data.client_stats[ip][2]
        lease = self.data.client_stats[ip][-1]
        self.layout.addWidget(ClientScreenClient(name, ip, mac, os, lease, self.suspend_client_func,
                                                 lambda x: self.remove_client_func(x, True)))
        self.main_frame.setFixedHeight(self.main_frame.height() + 210)

    def remove_client(self, ip):
        for i in range(1, self.layout.count()):
            if self.layout.itemAt(i).widget().ip == ip:
                self.layout.itemAt(i).widget().setParent(None)
                self.layout.removeItem(self.layout.itemAt(i))
                break
        self.main_frame.setFixedHeight(self.main_frame.height() - 210)

    def update_clients(self):
        while True:
            ip = self.data.client_update.get()
            for i in range(1, self.layout.count()):
                if self.layout.itemAt(i).widget().ip == ip:
                    mac, name, os = self.data.client_stats[ip][:3]
                    lease = self.data.client_stats[ip][-1]
                    self.layout.itemAt(i).widget().update_client(mac=mac, name=name, os=os, lease=lease)
                    break
