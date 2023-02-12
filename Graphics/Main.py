import sys
from Graphics.MainWindow import MainWindow
from Graphics.Screens import MainScreen, ClientsScreen
from PyQt5 import QtWidgets


class Graphics:

    def __init__(self, mac, addr, mask, mtu, iface, stop_func, remove_client_func):
        self.mac = mac
        self.addr = addr
        self.mask = mask
        self.mtu = mtu
        self.iface = iface
        self.last_time = None
        self._stop = False
        self.stop_func = stop_func
        self.remove_client_func = remove_client_func
        self.rules = []

    def add_pkt(self, time, pkt, new_comm):
        self.root.add_pkt(time, pkt, new_comm)

    def add_client(self, ip, mac, name):
        self.root.add_client(ip, mac, name)

    def remove_client(self, ip):
        self.root.remove_client(ip)

    def log(self, data):
        self.root.add_log(data)

    def is_active(self):
        return hasattr(self, 'root')

    def start(self):
        self.app = QtWidgets.QApplication(sys.argv)
        self.root = MainWindow(self.remove_client_func)
        self.screen = MainScreen.MainScreen(self.root)
        # self.screen = ClientsScreen.ClientsScreen(self.root)
        self.root.set_screen(self.screen)
        self.root.add_log('Router up!')
        self.root.resize(1200, 600)
        self.root.show()
        print('GUI loaded!')
        self.app.exec_()
        self.stop_func()
