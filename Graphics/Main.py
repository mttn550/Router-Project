import os
import sys
from Graphics.MainWindow import MainWindow
from Graphics.Screens import MainScreen, ClientsScreen, DHCP_Screen
from PyQt5 import QtWidgets, QtCore, QtGui


class Graphics(QtCore.QObject):

    def __init__(self, mac, addr, mask, mtu, min_mtu, max_mtu, dos_rate, thread_count, db_name, iface, lease_time,
                 stop_func, remove_client_func, change_free_ip_func, update_dns):
        super().__init__()
        self.mac = mac
        self.addr = addr
        self.mask = mask
        self.mtu = mtu
        self.min_mtu = min_mtu
        self.max_mtu = max_mtu
        self.dos_rate = dos_rate
        self.thread_count = thread_count
        self.db_name = db_name
        self.iface = iface
        self.lease_time = lease_time
        self.last_time = None
        self._stop = False
        self.stop_func = stop_func
        self.remove_client_func = remove_client_func
        self.change_free_ip_func = change_free_ip_func
        self.update_dns = update_dns
        self.dns_blacklist = []

    def set_attack_funcs(self, attack_manager):
        self.attack_manager = attack_manager

    def set_router_manager(self, router_manager):
        self.router_manager = router_manager

    def add_pkt(self, time, pkt, new_comm):
        if self.is_active():
            self.root.add_pkt(time, pkt, new_comm)

    def add_client(self, data):
        ip, mac, name = data
        self.root.add_client(ip, mac, name)

    def remove_client(self, ip):
        self.root.remove_client(ip)

    def log(self, data):
        self.root.add_log(data)

    def is_active(self):
        return hasattr(self, 'root')

    def start(self, free_ip):
        self.app = QtWidgets.QApplication(sys.argv)
        QtGui.QFontDatabase.addApplicationFont(os.getcwd() + r'\Graphics\JetBrainsMono.ttf')
        self.root = MainWindow(self.lease_time, free_ip, self.addr, self.mask, self.mtu, self.dos_rate,
                               self.thread_count, self.min_mtu, self.max_mtu, self.db_name,
                               self.remove_client_func, self.change_free_ip_func, self.attack_manager,
                               self.update_dns, self.dns_blacklist, self.router_manager)
        self.screen = MainScreen.MainScreen(self.root)
        self.root.set_screen(self.screen)
        self.root.add_log('Router up!')
        self.root.resize(1200, 600)
        self.root.show()
        print('GUI loaded!')
        self.app.exec_()
        self.stop_func()
