from PyQt5 import QtCore, QtGui, QtWidgets


class ClientsScreen(QtWidgets.QWidget):

    def __init__(self, root):
        super().__init__()

        self.NAME = 'Clients'
        self.data = root.data
        layout = QtWidgets.QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

        main_frame = QtWidgets.QFrame()
        layout.addWidget(main_frame)
        main_frame.setMinimumSize(750, 200)
        layout2 = QtWidgets.QVBoxLayout()
        main_frame.setLayout(layout2)

        layout2.addWidget(QtWidgets.QLabel('this is a client'))
        # DATA: NAME, IP, MAC, OS, LEASE TTL (root -> data)
        # OPTIONS: DISCONNECT (stop traffic - possible to resume), REMOVE (entirely - DHCPNACK?), VIEW ACTIVE RULES
