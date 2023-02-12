from PyQt5 import QtCore, QtGui, QtWidgets
from threading import Thread


class MainScreenStats(QtWidgets.QFrame):

    def __init__(self, data, parent=None):
        super().__init__(parent)

        layout = QtWidgets.QHBoxLayout()
        self.setLayout(layout)
        self.setMinimumSize(200, 100)

        self.data = data
        self.tcp = MainScreenProtoStats('TCP', data)
        self.udp = MainScreenProtoStats('UDP', data)
        self.icmp = MainScreenProtoStats('ICMP', data)
        layout.addLayout(self.tcp)
        layout.addLayout(self.udp)
        layout.addLayout(self.icmp)
        Thread(target=self.update_stats, daemon=True).start()

    def update_stats(self):
        while True:
            self.data.update.wait()
            self.data.update.clear()
            self.tcp.update_stats()
            self.udp.update_stats()
            self.icmp.update_stats()


class MainScreenProtoStats(QtWidgets.QVBoxLayout):

    def __init__(self, proto, data, parent=None):
        super().__init__(parent)
        self.data = data
        self.proto = proto
        header_font = QtGui.QFont('JetBrains Mono', 12)
        header_font.setBold(True)
        font = QtGui.QFont('JetBrains Mono', 10)

        self.header = QtWidgets.QLabel()
        self.header.setFont(header_font)
        self.header.setText(proto)
        self.header.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.addWidget(self.header)

        self.percent = QtWidgets.QLabel()
        self.percent.setFont(font)
        self.percent.setText('Total packets: 0%')
        self.percent.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.addWidget(self.percent)

        self.comm = QtWidgets.QLabel()
        self.comm.setFont(font)
        self.comm.setText('Sessions started: 0' if proto.upper() != 'ICMP' else 'Packets sent: 0')
        self.comm.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.addWidget(self.comm)

    def update_stats(self):
        count, sessions = eval(f'self.data.{self.proto.lower()}()')
        if self.data.total() == 0:
            self.percent.setText('Total packets: 0%')
        else:
            self.percent.setText(f'Total packets: {int(count / self.data.total() * 100)}%')
        self.comm.setText(f'Sessions started: {sessions}' if self.proto.upper() != 'ICMP'
                          else f'Packets sent: {sessions}')
