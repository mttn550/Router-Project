from Base.Packet import IP, UDP
from socket import inet_ntoa
from copy import deepcopy
from threading import Event


class AttackHandler:

    def __init__(self, critical_per_second, log_func):
        self.cache = {}
        self.blacklist = []
        self.whitelist = []
        self.blacklist_changed = Event()
        self.crit = critical_per_second
        self.log = log_func
        self.sec = None

    def is_in_blacklist(self, ip):
        return ip in self.blacklist

    def add_to_blacklist(self, ip):
        if ip not in self.blacklist:
            self.blacklist.append(ip)
            self.log(f'Suspended service to {inet_ntoa(ip)}.')

    def remove_from_blacklist(self, ip):
        if ip in self.blacklist:
            self.blacklist.remove(ip)
            self.log(f'Now accepting packets from {inet_ntoa(ip)}.')

    def add_to_whitelist(self, ip):
        if ip not in self.whitelist:
            self.whitelist.append(ip)
            self.log(f'Set {inet_ntoa(ip)} as a trusted host.')

    def remove_from_whitelist(self, ip):
        if ip in self.whitelist:
            self.whitelist.remove(ip)
            self.log(f'Now checking for attacks from host {inet_ntoa(ip)}.')

    def handler(self, time, pkt):
        if not pkt.haslayer(IP) or (pkt[2] is UDP and 53 in (pkt[2].sport, pkt[2].dport)) or \
                pkt[1].src in self.whitelist:
            return False
        if pkt[1].src in self.blacklist:
            print('Blocked')
            return True
        if self.sec is None: self.sec = time
        elif time - self.sec >= 1:
            cache = self.cache.copy()
            for key in cache.keys():
                cache[key] = 0
            self.cache = cache
            self.sec = int(time)
        packet = deepcopy(pkt[1])
        temp = packet
        while type(temp) != bytes:
            for i in ('sport', 'dport', 'checksum', 'id', 'frag_index'):
                if hasattr(temp, i):
                    if type(getattr(temp, i)) == int:
                        setattr(temp, i, 0)
                    elif type(getattr(temp, i)) == bytes:
                        setattr(temp, i, b'\x00' * len(getattr(temp, i)))
                    elif type(getattr(temp, i)) == str:
                        setattr(temp, i, '0' * len(getattr(temp, i)))
            temp = temp.payload
        data = packet.parse()
        if data in self.cache.keys():
            self.cache[data] += 1
            if self.cache[data] >= self.crit:
                self.blacklist.append(pkt[1].src)
                self.log(f'DOS attempt detected by {inet_ntoa(pkt[1].src)}. '
                         f'Ignoring future messages from {inet_ntoa(pkt[1].src)}.')
                self.blacklist_changed.set()
                return True
        else:
            self.cache[data] = 1
        return False
