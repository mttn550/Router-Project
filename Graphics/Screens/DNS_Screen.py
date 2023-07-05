from PyQt5 import QtCore, QtGui, QtWidgets
from ..Widgets.DNS_Table import DNS_Table
from Services.DNS import DNS
import re


DOMAIN_REGEX = re.compile(r'^(\w+\.)+\w+$')


class DNS_Screen(QtWidgets.QScrollArea):

    def __init__(self, root, update_dns, dns_blacklist):
        super().__init__()

        self.NAME = 'DNS'
        self.data = root.data
        self.update_dns = update_dns
        self.setWidgetResizable(True)
        self.layout = QtWidgets.QVBoxLayout()
        self.dns_blacklist = dns_blacklist

        self.main_frame = QtWidgets.QFrame()
        self.setMinimumSize(810, 300)
        self.main_frame.setMinimumWidth(790)
        self.main_frame.setLayout(self.layout)
        self.setWidget(self.main_frame)
        self.layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        self.layout.setSpacing(10)

        header_font = QtGui.QFont('Arial', 24)
        header_font.setBold(True)
        self.layout.addWidget(QtWidgets.QLabel('DNS', font=header_font))

        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.table = DNS_Table(update_dns)
        self.layout.addWidget(self.table)

        btn_layout = QtWidgets.QHBoxLayout()
        btn1 = QtWidgets.QPushButton('+')
        btn1.setFixedSize(30, 30)
        btn1.clicked.connect(self.table.add_row)
        btn3 = QtWidgets.QPushButton('-')
        btn3.setFixedSize(30, 30)
        btn3.clicked.connect(lambda: self.table.removeRow(self.table.selectionModel().selectedRows()[0].row()) if \
                                     self.table.selectionModel().selectedRows() else None)
        btn2 = QtWidgets.QPushButton('Update Custom Domains')
        btn2.setFixedHeight(30)
        btn2.clicked.connect(self.table.save)
        btn_layout.addWidget(btn1)
        btn_layout.addWidget(btn2)
        btn_layout.addWidget(btn3)
        self.layout.addLayout(btn_layout)

        self.blacklist = QtWidgets.QListWidget()
        self.blacklist.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.blacklist.setMinimumSize(200, 50)
        for i in dns_blacklist:
            if not (i.startswith('www.') and i.count('.') > 1):
                self.blacklist.addItem(i)
                self.blacklist.item(self.blacklist.count() - 1).setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        add_remove_layout = QtWidgets.QHBoxLayout()
        remove_btn = QtWidgets.QPushButton('Remove from Blacklist')
        remove_btn.clicked.connect(self.remove_from_blacklist)
        add_remove_layout.addWidget(remove_btn)

        self.blacklist_field = QtWidgets.QLineEdit()
        add_layout = QtWidgets.QHBoxLayout()
        add_layout.addWidget(self.blacklist_field)
        btn = QtWidgets.QPushButton('Add Domain to Blacklist')
        btn.clicked.connect(self.add_to_blacklist)
        add_remove_layout.addLayout(add_layout)
        add_remove_layout.addWidget(btn)

        self.layout.addWidget(self.blacklist)
        self.layout.addLayout(add_remove_layout)

    def add_to_blacklist(self):
        domain = self.blacklist_field.text()
        if domain.startswith('www.') and domain.count('.') > 1: domain = domain[4:]
        if DOMAIN_REGEX.match(domain):
            self.dns_blacklist.append(domain)
            self.update_dns(b'2', DNS.translate_domain(domain), b'')
            self.dns_blacklist.append('www.' + domain)
            self.update_dns(b'2', DNS.translate_domain('www.' + domain), b'')
            self.blacklist.addItem(domain)
            print(self.dns_blacklist)

    def remove_from_blacklist(self):
        domain = self.blacklist.selectedItems()[0].text()
        if domain in self.dns_blacklist:
            self.dns_blacklist.remove(domain)
            self.update_dns(b'2', DNS.translate_domain(domain), b'')
            self.dns_blacklist.remove('www.' + domain)
            self.update_dns(b'2', DNS.translate_domain('www.' + domain), b'')
            print(self.dns_blacklist)
            for i in range(self.blacklist.count()):
                if self.blacklist.item(i).text() == domain:
                    self.blacklist.takeItem(i)
                    break
