from Base.Packet import Ethernet, IP, UDP
from socket import inet_ntoa
from random import getrandbits as grb
import pcap, copy


class DNS_Cache:

    def __init__(self, iface, out_addr, addr, server):
        self.data = {'.'.join((*reversed(addr.split('.')), 'in-addr.arpa')):
                     ((b'\x00\x0c', '.'.join((*reversed(addr.split('.')), 'in-addr.arpa')), 'local.Home', b'\x11\x22\x33\x44'),)}
        print(self.data)
        self.out_addr = out_addr
        self.server = server
        self.pcap = pcap.pcap(name=iface, promisc=True, immediate=True)
        self.pcap.setfilter(f'udp and src port 53 and dst port 55555 and dst net {inet_ntoa(out_addr[1])}')

    def get_answers(self, pkt):
        pkt, = pkt
        data = pkt[3]
        requests = DNS.get_requests(data)
        print(requests)
        packets = []
        for request in requests:
            ans = self[request]
            pkt1 = copy.deepcopy(pkt)
            pkt1.src, pkt1.dst = pkt1.dst, pkt1.src
            pkt1[1].src, pkt1[1].dst = pkt1[1].dst, pkt1[1].src
            pkt1[2].sport, pkt1[2].dport = pkt1[2].dport, pkt1[2].sport
            pkt1[2].payload = DNS.response_msg(data[:2], request[0], ans)
            packets.append(pkt1)
        return packets

    def __getitem__(self, tup):
        domain, type = tup
        if domain in self.data.keys() and any(i[0] == type for i in self.data[domain]):
            return tuple(i for i in self.data[domain] if i[0] in (type, b'\x00\x02') or i[1] != domain)
        data = DNS.request_msg(bytes.fromhex(hex(grb(16))[2:]), domain, type)
        udp_pkt = UDP({'dport': 53, 'sport': 55555, 'payload': data})
        ip_pkt = IP({'proto': 17, 'src': self.out_addr[1], 'dst': self.server[0], 'payload': udp_pkt})
        pkt = Ethernet((self.out_addr[0], self.server[1], b'\x08\x00', ip_pkt))
        pkt[2].calc_checksum(self.out_addr[1], self.server[0])
        pkt[1].calc_checksum()
        self.pcap.sendpacket(pkt.parse())
        for time, pkt in self.pcap:
            pkt = Ethernet(pkt)
            pkt.payload = IP(pkt.payload)
            pkt.payload.payload = UDP(data=pkt.payload.payload, length=pkt.payload.len - pkt.payload.hlen)
            ans = pkt[3]
            break
        ans = ans[16 + len(DNS.translate_domain(domain)):]
        result = []
        temp = ans
        while temp:
            domain_len = DNS.get_addr_from_bytes(temp, ans)[1]
            data_len = int.from_bytes(temp[domain_len + 8: domain_len + 10], 'big')
            result.append((temp[domain_len: domain_len + 2], temp[:domain_len + 4], temp[domain_len + 8: domain_len + 8 + data_len],
                           int.from_bytes(temp[domain_len + 4: domain_len + 8], 'big')))
            temp = temp[domain_len + 8 + data_len:]
        if domain in self.data.keys(): self.data[domain] += result
        else: self.data[domain] = result
        return tuple(i for i in result if i[0] in (type, b'\x00\x02') or i[1] != domain)

    def tick(self):
        new_data = copy.deepcopy(self.data)
        for key, value in new_data.items():
            new_value = []
            for entry in value:
                if entry[-1] > 1 or entry[-1] < 0:
                    new_value.append((*entry[:-1], entry[-1] - 1))
            if new_value: new_data[key] = new_value
        self.data = new_data


class DNS:

    @staticmethod
    def request_msg(transc_id: bytes, domain: str, dtype: bytes):
        return transc_id + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + DNS.translate_domain(domain) + dtype + b'\x00\x01'

    @staticmethod
    def response_msg(transc_id: bytes, domain: str, answers):
        data = transc_id + b'\x81\x80\x00\x01' + len(answers).to_bytes(2, 'big') + \
               b'\x00\x00\x00\x00' + DNS.translate_domain(domain) + b'\x00\x01\x00\x01'
        for answer in answers:
            data += answer[1] + answer[3].to_bytes(4, 'big') + answer[2]
        return data

    @staticmethod
    def translate_domain(domain: str):
        data = b''
        if domain != '':
            for i in domain.split('.'):
                data += len(i).to_bytes(1, 'big') + i.encode('utf-8')
        return data + b'\x00'

    @staticmethod
    def get_addr_from_bytes(rr: bytes, data: bytes):
        addr = ''
        sum = 0; ref = False
        while True:
            num, rr = rr[0], rr[1:]
            if num == 0:
                break
            elif bin(num)[2:].zfill(8)[:4] == bin(0xc0)[2:].zfill(8)[:4]:
                index = int(bin(num - 0xc0)[2:].zfill(8) + bin(rr[0])[2:].zfill(8), 2)
                rr = data[index:]
                if not ref: sum += 1
                ref = True
                continue
            addr += rr[:num].decode() + '.'
            if not ref: sum += num + 1
            rr = rr[num:]
        return addr[:-1], sum

    @staticmethod
    def get_answers(domain: str, data: bytes):
        answers = []
        temp = data[16 + len(DNS.translate_domain(domain)):]
        while temp:
            addr, num = DNS.get_addr_from_bytes(temp, data)
            if addr == '':
                addr = '<Root>'
            temp = temp[num + 1:]
            if temp[:2] == b'\x00\x02':  # Type NS
                ns_addr, num = DNS.get_addr_from_bytes(temp[10:], data)
                answers.append((b'\x00\x02', addr, ns_addr, int.from_bytes(temp[4:8], 'big')))
                temp = temp[11 + num:]
            elif temp[:2] == b'\x00\x01':  # Type A
                answers.append((temp[:2], addr, inet_ntoa(temp[10: 14]), int.from_bytes(temp[4:8], 'big')))
                temp = temp[14:]
            elif temp[:2] == b'\x00\x05':  # Type CNAME
                cname_addr, num = DNS.get_addr_from_bytes(temp[10:], data)
                answers.append((temp[:2], addr, cname_addr, temp[4:8]))
                temp = temp[11 + num:]
            elif temp[:2] == b'\x00\x1c':  # Type AAAA
                answers.append((temp[:2], addr, temp[10: 10 + int.from_bytes(temp[8:10], 'big')], int.from_bytes(temp[4:8], 'big')))
                temp = temp[10 + int.from_bytes(temp[8:10], 'big'):]
            elif temp[:2] == b'\x00\x06':  # Type SOA
                ttl = int.from_bytes(temp[4:8], 'big')
                ns, num1 = DNS.get_addr_from_bytes(temp[10:], data)
                temp = temp[11 + num1:]
                mail, num2 = DNS.get_addr_from_bytes(temp, data)
                temp = temp[num2 + 1:]
                serial, refresh, retry, expire, min_ttl = temp[:4], temp[4:8], temp[8:12], temp[12:16], temp[16:20]
                answers.append((ns, mail, serial, refresh, retry, expire, min_ttl, ttl))
                temp = temp[20:]
            else:
                print(temp[:2])
        return answers

    @staticmethod
    def get_requests(data):
        num = int.from_bytes(data[4:6], 'big')
        index = 12
        result = []
        for i in range(num):
            temp = DNS.get_addr_from_bytes(data[index:], data)
            domain = temp[0]
            index += temp[1] + 1
            type = data[index: index + 2]
            result.append((domain, type))
        return result
