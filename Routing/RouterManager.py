from Base.Sniffer import Sniffer
import socket as s
import threading
import select
from time import sleep


class Router:

    def __init__(self, ip, sock, send_pkt):
        self.ip = ip
        self.messages = []
        self.sock = sock
        self.clients = set()
        self.active = True
        self.send_pkt = send_pkt
        self.clients_changed = threading.Event()
        threading.Thread(target=self.communicate, daemon=True).start()

    def add_client(self, ip):
        self.clients.add(ip)
        self.clients_changed.set()

    def remove_client(self, ip):
        if ip in self.clients:
            self.clients.remove(ip)
            self.clients_changed.set()

    def communicate(self):
        buffer = 1520
        while True:
            try:
                readable, writeable, _ = select.select([self.sock], [self.sock], [])
            except ValueError:  # Disconnecting from router
                self.active = False
                break
            if readable:
                data = b''
                while True:
                    try:
                        new_data = self.sock.recv(buffer)
                    except s.error:
                        self.active = False
                        break
                    data += new_data
                    if len(new_data) < buffer: break
                if not self.active: break
                if not data:
                    self.active = False
                    break
                if data[:4] == b'\x00\x00\x00\x00':
                    if data[4] == 0x00:
                        self.remove_client(data[5:9])
                    elif data[4] == 0x01:
                        self.add_client(data[5:9])
                else:
                    print('got mes')
                    self.send_pkt(Sniffer.construct_packet(data[4:]))
            if writeable:
                if self.messages:
                    print('sent mes')
                    self.sock.send(self.messages.pop(0))
        print('Disconnected')


class RouterManager:

    def __init__(self, clients, send_pkt):
        self.routers = set()
        self.prev_clients = {}
        self.clients = clients
        self.send_pkt = send_pkt
        self.sock = s.socket(s.AF_INET, s.SOCK_STREAM)

    def add_router(self, router):
        print('found')
        self.routers.add(router)

    def remove_router(self, router):
        if router in self.routers:
            self.routers.remove(router)

    def all_clients(self):
        result = {}
        for router in self.routers:
            for client in router.clients:
                result[client] = router
        return result

    def alert_clients(self):
        while True:
            routers = set()
            for router in self.routers:
                if router.active:
                    routers.add(router)
            self.routers = routers
            clients = self.clients.keys()
            prev_clients = self.prev_clients.keys()
            if clients != prev_clients:
                remove_ips = []
                for i in prev_clients:
                    if i not in clients:
                        remove_ips.append(b'\x00\x00\x00\x00\x00' + i)
                add_ips = []
                for i in clients:
                    if i not in prev_clients:
                        add_ips.append(b'\x00\x00\x00\x00\x01' + i)
                for router in self.routers:
                    router.messages += remove_ips + add_ips
                self.prev_clients = self.clients.copy()
            sleep(1)

    def accept_routers(self):
        self.sock.bind(('', 44444))
        self.sock.listen(5)
        while True:
            readable, _, _ = select.select([self.sock], [], [])
            sock, addr = self.sock.accept()
            if select.select([sock], [], [], 0.2):
                if sock.recv(1024).decode() == 'PING':
                    sock.send('PONG'.encode())
                    router = Router(addr[0], sock, self.send_pkt)
                    for client in self.clients.keys():
                        router.messages.append(b'\x00\x00\x00\x00\x01' + client)
                    self.add_router(router)

    def contact_router(self, ip):
        sock = s.socket(s.AF_INET, s.SOCK_STREAM)
        try: sock.connect((ip, 44444))
        except s.error:
            print('Could not connect to router.')
            return
        sock.send('PING'.encode())
        if select.select([sock], [], [], 0.2):
            if sock.recv(1024).decode() == 'PONG':
                router = Router(ip, sock, self.send_pkt)
                for client in self.clients.keys():
                    router.messages.append(b'\x00\x00\x00\x00\x01' + client)
                self.add_router(router)
                print('Connected!')
                return
        print('Not a router.')
