from socket import inet_ntoa, inet_aton
from Services.DNS import DNS
from PyQt5 import QtCore, QtGui, QtWidgets
import re


COLUMNS = ('Domain Name', 'Address')
IP_REGEX = re.compile(r'^([1-2]?\d{1,2}.){3}[1-2]?\d{1,2}$')
DOMAIN_REGEX = re.compile(r'^(\w+\.)+\w+$')


class DNS_Table(QtWidgets.QTableWidget):

    def __init__(self, update_func, parent=None):
        super().__init__(0, len(COLUMNS), parent)
        self.update_func = update_func

        self.setHorizontalHeaderLabels(COLUMNS)
        self.setSelectionMode(QtWidgets.QTableWidget.SelectionMode.SingleSelection)
        self.setSelectionBehavior(QtWidgets.QTableWidget.SelectionBehavior.SelectRows)
        self.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.horizontalHeader().setDefaultSectionSize(300)
        self.horizontalHeader().setMinimumSectionSize(150)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setVisible(False)
        item = QtWidgets.QTableWidgetItem()
        item.setFlags(QtCore.Qt.ItemFlag.ItemIsEnabled)
        item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
        item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsSelectable)
        item.setCheckState(QtCore.Qt.CheckState.Unchecked)
        self.setItemPrototype(item)
        self.domain_fields = {}
        self.address_fields = {}
        self.add_row()

    def add_row(self):
        count = self.rowCount()
        self.insertRow(count)
        domain_field = QtWidgets.QLineEdit()
        addr_field = QtWidgets.QLineEdit('0.0.0.0')
        self.domain_fields[count] = domain_field
        self.address_fields[count] = addr_field
        self.setCellWidget(count, 0, domain_field)
        self.setCellWidget(count, 1, addr_field)

    def save(self):
        to_update = []
        for i in range(self.rowCount()):
            domain, addr = self.domain_fields[i].text().lower(), self.address_fields[i].text().lower()
            if domain.startswith('www.') and domain.count('.') > 1: domain = domain[4:]
            if IP_REGEX.match(addr) and not any(int(i) > 255 for i in addr.split('.')) and \
                    int(addr.split('.')[0]) != 0 and addr != '255.255.255.255' and DOMAIN_REGEX.match(domain):
                to_update.append((DNS.translate_domain(domain), inet_aton(addr)))
                to_update.append((DNS.translate_domain('www.' + domain), inet_aton(addr)))
            else:
                print('Error')
                break
        self.update_func(b'1', b'', b'')
        for domain, addr in to_update:
            self.update_func(b'1', domain, addr)
