class Ethernet:

    def __init__(self, data=()):
        '''
        :param data: src, dst, proto, payload
        '''
        if type(data) == bytes:
            self.dst = data[:6]
            self.src = data[6:12]
            self.proto = data[12:14]
            self.payload = data[14:]
        elif type(data) == tuple:
            self.src, self.dst, self.proto, self.payload = data

    def ig_bit(self):
        return self.dst[0] % 2 == 1

    def haslayer(self, item):
        if type(item) == bytes: return True
        pkt = self
        while True:
            if type(pkt) == item: return True
            if type(pkt) == bytes: return False
            pkt = pkt.payload

    def __getitem__(self, item):
        result = self
        if type(item) == int:
            for i in range(item):
                result = result.payload
            return result
        while type(result) != bytes:
            result = result.payload
            if type(result) == item: return result
        raise TypeError

    def fragment(self, mtu):
        if self.proto != b'\x08\x00' or self.payload.flags['DF'] == '1':
            return self.parse(),
        data = self.payload.payload.parse()
        result = []
        num = ((mtu - self.payload.hlen) // 8) * 8
        for i in range(0, len(data), num):
            ip = IP(self.payload.parse_header() + data[i: num + i]); ip.len = len(ip.parse())
            if i + num < len(data): ip.flags['MF'] = '1'
            ip.frag_index = bin(i // 8)[2:].zfill(13)
            ip.len = len(ip.parse())
            ip.calc_checksum()
            result.append(Ethernet((self.src, self.dst, self.proto, ip)).parse())
        return result

    def parse(self):
        if type(self.payload) == bytes:
            return self.dst + self.src + self.proto + self.payload
        return self.dst + self.src + self.proto + self.payload.parse()


class ARP:

    def __init__(self, data={}):
        if type(data) == bytes:
            self.htype = data[:2]; self.ptype = data[2:4]
            self.hlen = data[4:5]; self.plen = data[5:6]
            self.code = int.from_bytes(data[6:8], 'big')
            self.smac = data[8:14]; self.src = data[14:18]
            self.dmac = data[18:24]; self.dst = data[24:28]
            self.payload = b''  # Makes it compatible with other protocols.

        elif type(data) == dict:
            # Setting the default properties:
            self.htype = b'\x00\x01'; self.ptype = b'\x08\x00'
            self.hlen = b'\x06'; self.plen = b'\x04'
            self.code = 1
            self.smac = b'\x00\x00\x00\x00\x00\x00'; self.src = b'\x00\x00\x00\x00'
            self.dmac = b'\xff\xff\xff\xff\xff\xff'; self.dst = b'\xff\xff\xff\xff'
            self.payload = b''
            # Setting the requested data:
            for key, value in data.items():
                setattr(self, key, value)

    def parse(self):
        return self.htype + self.ptype + self.hlen + self.plen + self.code.to_bytes(2, 'big') + self.smac + self.src + \
            self.dmac + self.dst


class IP:

    def __init__(self, data={}):
        if type(data) == bytes:
            self.type = int(bin(data[0])[2:].zfill(8)[:4], 2)
            self.hlen = int(bin(data[0])[2:].zfill(8)[4:], 2) * 4
            self.len = int.from_bytes(data[2:4], 'big')
            self.id = data[4:6]
            flag = bin(int.from_bytes(data[6:8], 'big'))[2:].zfill(16)
            self.flags = { 'R': flag[0], 'DF': flag[1], 'MF': flag[2] }
            self.frag_index = flag[3:]
            self.ttl, self.proto = data[8:10]
            self.checksum = int.from_bytes(data[10:12], 'big')
            self.src = data[12:16]; self.dst = data[16:20]
            self.extra = data[20:self.hlen]
            self.payload = data[self.hlen:]

        elif type(data) == dict:
            self.type = 4
            self.hlen = 20
            self.len = -1
            self.id = b'\x00\x00'
            self.flags = {'R': '0', 'DF': '0', 'MF': '0'}
            self.frag_index = '0' * 13
            self.ttl = 128
            self.proto = 0
            self.checksum = 0
            self.src = b'\x00\x00\x00\x00'
            self.dst = b'\xff\xff\xff\xff'
            self.extra = b''
            self.payload = b''
            for key, value in data.items():
                setattr(self, key, value)

    def haslayer(self, item):
        if type(item) == bytes: return True
        pkt = self
        while True:
            if type(pkt) == item: return True
            if type(pkt) == bytes: return False
            pkt = pkt.payload

    def __getitem__(self, item):
        result = self
        if type(item) == int:
            for i in range(item):
                result = result.payload
            return result
        while type(result) != bytes:
            result = result.payload
            if type(result) == item: return result
        raise TypeError

    def calc_checksum(self):
        self.checksum = 0
        data = self.parse()[:self.hlen]
        num = 0
        for i in range(0, len(data), 2):
            num += int.from_bytes(data[i:i + 2], 'big')
            num = int(hex(num)[2:].zfill(8)[:4], 16) + int(hex(num)[2:].zfill(8)[4:], 16)
            num = num & 0xffff
        self.checksum = (~num) & 0xffff

    def parse_header(self):
        return int(bin(self.type)[2:].zfill(4) + bin(self.hlen // 4)[2:].zfill(4), 2).to_bytes(1, 'big') + \
               b'\x00' + self.len.to_bytes(2, 'big') + self.id + \
               int(''.join(self.flags.values()) + self.frag_index, 2).to_bytes(2, 'big') + \
               self.ttl.to_bytes(1, 'big') + self.proto.to_bytes(1, 'big') + \
               self.checksum.to_bytes(2, 'big') + self.src + self.dst

    def parse(self):
        if type(self.payload) == bytes: payload = self.payload
        else: payload = self.payload.parse()
        if self.len == -1: self.len = self.hlen + len(self.payload)
        return self.parse_header() + payload


class UDP:

    def __init__(self, data={}, length=-1):
        if type(data) == bytes:
            self.sport = int.from_bytes(data[:2], 'big')
            self.dport = int.from_bytes(data[2:4], 'big')
            self.checksum = int.from_bytes(data[6:8], 'big')
            if length == -1: self.payload = data[8:]
            else: self.payload = data[8:length]

        elif type(data) == dict:
            self.sport = 0
            self.dport = 0
            self.checksum = 0
            self.payload = b''
            for key, value in data.items():
                setattr(self, key, value)

    def __len__(self):
        return 8 + len(self.payload)

    def __getitem__(self, item):
        result = self
        if type(item) == int:
            for i in range(item):
                result = result.payload
            return result
        while type(result) != bytes:
            result = result.payload
            if type(result) == item: return result
        raise TypeError

    def calc_checksum(self, src, dst):
        self.checksum = 0
        data = src + dst + b'\x00\x11' + (8 + len(self.payload)).to_bytes(2, 'big') + self.parse()
        data += b'\x00' * (len(data) % 2)
        num = 0
        for i in range(0, len(data), 2):
            num += int.from_bytes(data[i:i + 2], 'big')
            num = int(hex(num)[2:].zfill(8)[:4], 16) + int(hex(num)[2:].zfill(8)[4:], 16)
        self.checksum = (~num) & 0xffff

    def parse_header(self):
        return self.sport.to_bytes(2, 'big') + self.dport.to_bytes(2, 'big') + \
               (8 + len(self.payload)).to_bytes(2, 'big') + self.checksum.to_bytes(2, 'big')

    def parse(self):
        return self.parse_header() + self.payload


class TCP:

    def __init__(self, data, length=-1):
        self.sport = int.from_bytes(data[:2], 'big'); self.dport = int.from_bytes(data[2:4], 'big')
        self.seq = data[4:8]; self.ack = data[8:12]
        flag = bin(int.from_bytes(data[12:14], 'big'))[2:].zfill(16)
        self.hlen = int(flag[:4], 2) * 4
        self.flags = {'Reserved': flag[4:7], 'N': flag[7], 'CWR': flag[8], 'E': flag[9], 'U': flag[10], 'A': flag[11],
                      'P': flag[12], 'R': flag[13], 'S': flag[14], 'F': flag[15]}
        self.window = data[14:16]
        self.checksum = int.from_bytes(data[16:18], 'big')
        self.urgent = data[18:20]
        self.extra = data[20:self.hlen]
        if length == -1: self.payload = data[self.hlen:]
        else: self.payload = data[self.hlen:length]

    def __len__(self):
        return len(self.parse())

    def __getitem__(self, item):
        result = self
        if type(item) == int:
            for i in range(item):
                result = result.payload
            return result
        while type(result) != bytes:
            result = result.payload
            if type(result) == item: return result
        raise TypeError

    def calc_checksum(self, src, dst):
        self.checksum = 0
        data = src + dst + b'\x00\x06' + (self.hlen + len(self.payload)).to_bytes(2, 'big') + self.parse()
        data += b'\x00' * (len(data) % 2)
        num = 0
        for i in range(0, len(data), 2):
            num += int.from_bytes(data[i:i + 2], 'big')
            num = int(hex(num)[2:].zfill(8)[:4], 16) + int(hex(num)[2:].zfill(8)[4:], 16)
        self.checksum = (~num) & 0xffff

    def parse_header(self):
        return self.sport.to_bytes(2, 'big') + self.dport.to_bytes(2, 'big') + self.seq + self.ack + \
               int(''.join((bin(self.hlen // 4)[2:].zfill(4), *self.flags.values())), 2).to_bytes(2, 'big') + \
               self.window + self.checksum.to_bytes(2, 'big') + self.urgent + self.extra

    def parse(self):
        return self.parse_header() + self.payload


class ICMP:

    def __init__(self, data, length=-1):
        if type(data) == bytes:
            self.type = data[0]
            self.code = data[1]
            self.checksum = int.from_bytes(data[2:4], 'big')
            self.id = data[4:6]
            self.seq = data[6:8]
            if length == -1: self.payload = data[8:]
            else: self.payload = data[8:length]
        elif type(data) == dict:
            self.type = 0
            self.code = 0
            self.checksum = 0
            self.id = b'\x00\x00'
            self.seq = b'\x00\x00'
            self.payload = b''
            for key, value in data.items():
                setattr(self, key, value)

    def __len__(self):
        return len(self.parse())

    def __getitem__(self, item):
        result = self
        if type(item) == int:
            for i in range(item):
                result = result.payload
            return result
        while type(result) != bytes:
            result = result.payload
            if type(result) == item: return result
        raise TypeError

    def calc_checksum(self):
        self.checksum = 0
        data = self.parse()
        data += b'\x00' * (len(data) % 2)
        num = 0
        for i in range(0, len(data), 2):
            num += int.from_bytes(data[i:i + 2], 'big')
            num = int(hex(num)[2:].zfill(8)[:4], 16) + int(hex(num)[2:].zfill(8)[4:], 16)
        self.checksum = (~num) & 0xffff

    def parse_header(self):
        return self.type.to_bytes(1, 'big') + self.code.to_bytes(1, 'big') + self.checksum.to_bytes(2, 'big') + \
               self.id + self.seq

    def parse(self):
        if type(self.payload) == bytes: payload = self.payload
        else: payload = self.payload.parse()
        return self.parse_header() + payload
