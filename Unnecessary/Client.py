class Client:

    def __init__(self, mac, addr):
        self.mac = mac
        self.addr = addr
        self.icmp = -1
        self.tcp_communications = {}


class Clients:

    def __init__(self):
        self.clients = []

    def __getitem__(self, item):
        for client in self.clients:
            if item in (client.mac, client.out_addr, client.icmp):
                return client
        return None

    def get_port(self, port):
        for client in self.clients:
            if port in client.tcp_communications.keys():
                return client
        return None

    def get_origin_port(self, port):
        for client in self.clients:
            for key, value in client.tcp_communications.items():
                if port == value[0]:
                    return key
        return None

    def __add__(self, item):
        self.clients.append(item)
        return self

    def __sub__(self, item):
        if item in self.clients:
            self.clients.remove(item)
        return self
