from PyQt5 import QtWidgets, QtGui, QtCore
from Graphics.Widgets.SniffTable import TableManager
from Graphics.Widgets.Statistics import MainScreenStats
from Graphics.Widgets.Clients import MainWindowClient
from Graphics.Widgets.HLine import HLine
from socket import inet_ntoa, inet_aton


class MainScreen(QtWidgets.QWidget):

    def __init__(self, root):
        super().__init__()

        self.NAME = 'Main'
        self.data = root.data
        layout = QtWidgets.QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
        self.table = TableManager()

        main_frame = QtWidgets.QFrame()
        layout.addWidget(main_frame)
        main_frame.setMinimumSize(750, 200)
        layout2 = QtWidgets.QVBoxLayout()
        main_frame.setLayout(layout2)

        header_font = QtGui.QFont('Arial', 20)
        header_font.setBold(True)
        header = QtWidgets.QLabel('Router Up and Running!', font=header_font)
        header.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet('padding: 20px')
        layout2.addWidget(header)
        layout2.addWidget(self.table)
        layout2.addWidget(HLine())

        cli_layout = QtWidgets.QHBoxLayout()
        self.cli = MainWindowClient()
        cli_layout.addWidget(self.cli)
        self.cli2 = MainWindowClient()
        cli_layout.addWidget(self.cli2)
        layout2.addLayout(cli_layout)
        self.tot_client = QtWidgets.QLabel()
        self.tot_client.setText('TOTAL: 0')
        font = QtGui.QFont('JetBrains Mono', 14)
        font.setBold(True)
        self.tot_client.setFont(font)
        self.tot_client.setMaximumSize(130, 90)
        cli_layout.addWidget(self.tot_client)
        layout2.addWidget(HLine())
        self.cli_queue = []
        for client in self.data.clients():
            client = inet_ntoa(client)
            self.add_client((client, *self.data.client_stats[client][:2]))

        self.stats = MainScreenStats(self.data)
        layout2.addWidget(self.stats)

        self.setMinimumSize(1029, 450)

    def add_client(self, data):
        if not self.cli.is_client():
            self.cli.update_client(data)
        elif not self.cli2.is_client():
            self.cli2.update_client(data)
        else:
            self.cli_queue.append(data)
        self.tot_client.setText(self.tot_client.text()[:7] + str(int(self.tot_client.text()[7:]) + 1))
        self.table.add_client(inet_aton(data[0]), data[1])

    def remove_client(self, ip):
        for cli in self.cli, self.cli2:
            if cli.ip.text()[2:] == ip:
                cli.remove_client()
                if self.cli_queue:
                    cli.update_client(self.cli_queue.pop(0))
                self.tot_client.setText(self.tot_client.text()[:7] + str(int(self.tot_client.text()[7:]) - 1))
                break
        self.table.remove_client(inet_aton(ip))

    def add_pkt(self, time, pkt):
        self.table.add(time, pkt)
