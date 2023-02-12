from PyQt5 import QtGui, QtWidgets


class MainWindowClient(QtWidgets.QFrame):

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QHBoxLayout(self)
        self.setLayout(layout)
        self.pic = QtWidgets.QLabel()
        self.pic.setMinimumSize(100, 100)
        self.pic.setMaximumSize(100, 100)
        self.pic.setMovie(QtGui.QMovie('loading.gif'))
        self.pic.movie().start()
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
        self.pic.setMovie(QtGui.QMovie('loading.gif'))
        self.pic.movie().start()
        self.ip.setText('')
        self.mac.setText('')
        self.name.setText('')

    def is_client(self):
        return not self.ip.text() == ''

