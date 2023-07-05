from threading import Event
from queue import Queue
from socket import inet_aton, inet_ntoa
import copy


class Statistics:

    def __init__(self, log, lease_time):
        self.indexes = {'tcp': 3, 'udp': 5, 'icmp': 7}
        self.client_stats = dict()  # Client IP: [MAC, Name, OS, TCP, TCP Sessions, UDP, UDP Sessions, ICMP, Lease TTL]
        self.client_stats[None] = ['', '', '', 0, 0, 0, 0, 0, -1]
        self.update = Event()
        self.client_update = Queue()
        self.lease_time = lease_time
        self.log = log
        self.highest = 0  # Highest amount of clients

    def total(self):
        return sum(sum(i[3::2]) for i in self.client_stats.values())

    def tcp(self):
        return sum(i[3] for i in self.client_stats.values()), sum(i[4] for i in self.client_stats.values())

    def udp(self):
        return sum(i[5] for i in self.client_stats.values()), sum(i[6] for i in self.client_stats.values())

    def icmp(self):
        return sum(i[7] for i in self.client_stats.values()), sum(i[7] for i in self.client_stats.values())

    def clients(self):
        return tuple(inet_aton(i) for i in self.client_stats.keys() if i is not None)

    def update_pkt(self, client, proto, new_comm=False, os=''):
        client = inet_ntoa(client)
        if not client in self.client_stats.keys(): return
        if not self.client_stats[client][2] and os:
            self.client_stats[client][2] = os
            self.log(f"{client}'s OS has been verified using p0f to be {os}.")
        if proto in self.indexes.keys():
            self.client_stats[client][self.indexes[proto]] += 1
            if proto != 'icmp':
                self.client_stats[client][self.indexes[proto] + 1] += int(new_comm)
            self.update.set()

    def add_client(self, client):
        self.client_stats[client[0]] = [client[1], client[2], '', 0, 0, 0, 0, 0, self.lease_time]
        if len(self.client_stats.keys()) > self.highest:
            self.highest = len(self.client_stats.keys())
        self.update.set()
        self.client_update.put(client[0])

    def remove_client(self, client):
        for i in range(3, 8):
            self.client_stats[None][i] += self.client_stats[client][i]
        del self.client_stats[client]
        self.update.set()

    def tick(self):
        keys = copy.copy(tuple(self.client_stats.keys()))
        for i in keys:
            if i is not None:
                self.client_stats[i][-1] -= 1
                self.client_update.put(i)
        del keys
