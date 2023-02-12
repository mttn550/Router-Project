import copy, socket


class Rules:

    def __init__(self):
        """
        Initializes the rules.
        keys: protocol, (dst IP, dst port) | (dst IP, ICMP type, ICMP seq)
        values: a set of (src IP, <src port, NAT port>, socket, TTL)
        """
        self.rules = {}
        self.base_ttl = 300  # seconds

    def __getitem__(self, item):
        protocol, addr, *data = item
        data = tuple(data)
        if not any(i in self.rules.keys() for i in ((protocol, addr), (protocol, (-1, -1)))): return None
        if not data: return next(iter(self.rules[(protocol, addr)]))
        port, pindex = data
        if (protocol, addr) in self.rules.keys(): conn = self.rules[(protocol, addr)].copy()
        else: conn = self.rules[(protocol, (-1, -1))].copy()
        result = None
        for item in conn:
            if item[pindex] == port:
                result = item
        del conn
        return result

    def __setitem__(self, key, value):
        if type(value[-1]) != int: value = (*value, 0)
        if key not in self.rules.keys(): self.rules[key] = set()
        self.rules[key].add(value)
        return self

    def keys(self):
        return self.rules.keys()

    def add_static(self, proto, port, dst, dport):
        if proto == 'tcp': sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif proto == 'udp': sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else: raise TypeError("Invalid Protocol: Must be 'tcp' or 'udp'.")
        sock.bind(('0.0.0.0', port))
        self.rules[(proto, (-1, -1))] = {(dst, dport, port, sock, -1)}

    def tick(self):
        keys = copy.copy(tuple(self.rules.keys()))
        for key in keys:
            new_rules = set()
            conn = self.rules[key].copy()
            for item in conn:
                if item[-1] > 1: new_rules.add((*item[:-1], item[-1] - 1))
                elif item[-1] == 1: item[-2].close()  # Close the socket.
                else: new_rules.add(item)
            for item in self.rules[key] - conn:
                new_rules.add(item)
            del conn
            self.rules[key] = new_rules
        if keys: del new_rules
        del keys
