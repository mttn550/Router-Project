from PyQt5 import QtCore, QtGui, QtWidgets
from socket import inet_ntoa
from threading import Thread


class BridgeScreen(QtWidgets.QScrollArea):

    def __init__(self, root, remove_client_func):
        super().__init__()

        self.NAME = 'Bridge'
        self.data = root.data
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
        self.layout.addWidget(QtWidgets.QLabel('Bridge', font=header_font))

        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        Thread(target=self.update_clients, daemon=True).start()
