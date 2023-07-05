from threading import Thread
from PyQt5 import QtCore


class GUI_Thread(Thread, QtCore.QObject):

    add_client_signal = QtCore.pyqtSignal(tuple)

    def __init__(self, func, args):
        super().__init__(daemon=True)
        QtCore.QObject.__init__(self)
        self.func = func
        self.args = args

    def run(self):
        generator = self.func(*self.args)
        while generator:
            result = next(generator)
            if result is not None:
                self.add_client_signal.emit(result)
