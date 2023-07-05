from Base.Packet import Ethernet, IP, UDP
from socket import inet_ntoa, inet_aton
from os import urandom
import pcap, copy


class DNS_Cache:

    def __init__(self, iface, out_addr, addr, server, name):
        self.data = {'.'.join((*reversed(addr.split('.')), 'in-addr.arpa')):
                         ((b'\x00\x0c', '.'.join((*reversed(addr.split('.')), 'in-addr.arpa')), name, -1),)}
        self.custom_tld = name.split('.')[-1].lower()
        self.custom_data = {}
        self.blacklist = []
        self.addr = addr
        self.out_addr = out_addr
        self.server = server
        self.pcap = pcap.pcap(name=iface, promisc=True, immediate=True)
        self.pcap.setfilter(f'udp and src port 53 and dst port 55555 and dst net {inet_ntoa(out_addr[1])}')
        self.pending_answers = set()

    def get_answers(self, pkt):
        pkt, = pkt
        data = pkt[3]
        requests, _ = DNS.get_requests(data)
        packets = []
        for request in requests:
            ans, rcode = self[request]
            pkt1 = copy.deepcopy(pkt)
            pkt1.src, pkt1.dst = pkt1.dst, pkt1.src
            pkt1[1].src, pkt1[1].dst = pkt1[1].dst, pkt1[1].src
            pkt1[2].sport, pkt1[2].dport = pkt1[2].dport, pkt1[2].sport
            pkt1[2].payload = DNS.response_msg(data[:2], request[0], request[1], ans, rcode)
            pkt1[1].len = -1
            pkt1[2].calc_checksum(pkt1[1].dst, pkt1[1].src)
            pkt1[1].calc_checksum()
            packets.append(pkt1)
        return packets

    def __getitem__(self, data):
        domain, type = data
        domain = domain.lower()
        if domain in self.blacklist and type == b'\x00\x01':
            return [(b'\x00\x01', domain, self.addr, -1)], 0
        elif domain.split('.')[-1] == self.custom_tld:
            if domain in self.custom_data.keys():
                if any(i[0] == type for i in self.custom_data[domain]):
                    return [i for i in self.custom_data[domain] if i[0] in type or i[1] != domain], 0
                return (), 2  # Server failed to complete the DNS request
            else:
                return (), 3  # Domain name does not exist
        elif domain in self.data.keys():
            if any(i[0] == type for i in self.data[domain]):
                # type NS / MX - I will provide the IP addresses of the Servers, if I know any.
                if type in (b'\x00\x02', b'\x00\x0f'):
                    result = []
                    result += [i for i in self.data[domain] if i[0] == type]
                    for i in result.copy():
                        addr = i[2] if type == b'\x00\x02' else DNS.get_addr_from_bytes(i[2][2:], i[2][2:])[0]
                        if addr in self.data.keys():
                            result += [j for j in self.data[addr] if j[0] in (b'\x00\x01', b'\x00\x1c')]
                    return result, 0
                else:
                    return [i for i in self.data[domain] if i[0] == type or i[1] != domain], 0
        transc_id = urandom(2)
        data = DNS.request_msg(transc_id, domain, type)
        udp_pkt = UDP({'dport': 53, 'sport': 55555, 'payload': data})
        ip_pkt = IP({'proto': 17, 'src': self.out_addr[1], 'dst': self.server[0], 'payload': udp_pkt})
        pkt = Ethernet((self.out_addr[0], self.server[1], b'\x08\x00', ip_pkt))
        pkt[2].calc_checksum(self.out_addr[1], self.server[0])
        pkt[1].calc_checksum()
        self.pcap.sendpacket(pkt.parse())
        for time, pkt in self.pcap:
            for i in self.pending_answers:
                if i[:2] == transc_id:
                    ans = i
                    self.pending_answers.remove(i)
                    break
            else:
                pkt = Ethernet(pkt)
                pkt.payload = IP(pkt.payload)
                pkt.payload.payload = UDP(data=pkt.payload.payload, length=pkt.payload.len - pkt.payload.hlen)
                ans = pkt[3]
                if ans[:2] != transc_id:
                    self.pending_answers.add(ans)
                    continue
            break
        answers = DNS.get_answers(ans)
        rcode = int(bin(ans[3])[2:].zfill(8)[4:], 2)
        if rcode == 0:  # There was no error - I will add the data.
            for ans in answers:
                if ans[0] == b'\x00\x29': continue
                if ans[1] in self.data.keys():
                    self.data[ans[1]].append(ans)
                else:
                    self.data[ans[1]] = [ans]
        return answers, rcode

    def add_custom_domain(self, domain, data):
        domain = domain.lower()
        if domain.split('.')[-1] != self.custom_tld: domain += '.' + self.custom_tld
        entry = []
        if type(data[0]) != bytes:
            for record in data:
                entry.append((record[0], *record[1:], -1))
        else:
            entry.append((*data, -1))
        if domain in self.custom_data.keys():
            self.custom_data[domain] += entry
        else:
            self.custom_data[domain] = entry

    def tick(self):
        new_data = copy.copy(self.data)
        for key, value in new_data.items():
            new_value = []
            for entry in value:
                if entry[-1] > 1:
                    new_value.append((*entry[:-1], entry[-1] - 1))
                elif entry[-1] < 0:
                    new_value.append(entry)
            if new_value: new_data[key] = new_value
        self.data = new_data


class DNS:

    @staticmethod
    def request_msg(transc_id: bytes, domain: str, dtype: bytes):
        return transc_id + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + \
               DNS.translate_domain(domain) + dtype + b'\x00\x01'

    @staticmethod
    def response_msg(transc_id: bytes, domain: str, dtype: bytes, answers, rcode: int):
        flags = (0x8180 + rcode).to_bytes(2, 'big')
        data = transc_id + flags + b'\x00\x01' + len([i for i in answers if i[0] != b'\x00\x06']).to_bytes(2, 'big') + \
            len([i for i in answers if i[0] == b'\x00\x06']).to_bytes(2, 'big') + b'\x00\x00' + DNS.translate_domain(domain) + dtype + b'\x00\x01'
        for answer in answers:
            if answer[0] == b'\x00\x29':
                data += DNS.translate_domain(answer[1]) + b'\x00\x29' + answer[2]
                continue
            ttl = 0x12345678 if answer[3] == -1 else answer[3]
            answer_addr = DNS.encode_answer(answer[0], answer[2])
            ans_bytes = DNS.translate_domain(answer[1]) + answer[0] + b'\x00\x01'
            ans_bytes += ttl.to_bytes(4, 'big') + len(answer_addr).to_bytes(2, 'big') + answer_addr
            data += ans_bytes
        return data

    @staticmethod
    def encode_answer(atype, answer):
        if atype == b'\x00\x02':  # Type NS
            return DNS.translate_domain(answer)
        elif atype == b'\x00\x01':  # Type A
            return inet_aton(answer)
        elif atype == b'\x00\x05':  # Type CNAME
            return DNS.translate_domain(answer)
        elif atype == b'\x00\x1c':  # Type AAAA
            return answer
        elif atype == b'\x00\x06':  # Type SOA
            return answer
        elif atype == b'\x00\x0f':  # Type MX
            return answer
        elif atype == b'\x00\x0c':  # Type PTR
            return DNS.translate_domain(answer)
        elif atype == b'\x00\x21':  # Type SRV
            return answer
        elif atype == b'\x00\x41':  # Type SOA
            return answer
        elif atype == b'\x00\x0c':  # Type PTR
            return DNS.translate_domain(answer)

    @staticmethod
    def translate_domain(domain: str):
        data = b''
        if domain != '' and domain != '<Root>':
            for i in domain.split('.'):
                data += len(i).to_bytes(1, 'big') + i.encode('utf-8')
        return data + b'\x00'

    @staticmethod
    def get_addr_from_bytes(rr: bytes, data: bytes):
        addr = ''
        sum = 0
        ref = False
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
        return result, index + 4

    @staticmethod
    def get_answers(data: bytes):
        answers = []
        temp = data[DNS.get_requests(data)[1]:]
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
                answers.append((temp[:2], addr, cname_addr, int.from_bytes(temp[4:8], 'big')))
                temp = temp[11 + num:]
            elif temp[:2] == b'\x00\x1c':  # Type AAAA
                answers.append((temp[:2], addr, temp[10: 10 + int.from_bytes(temp[8:10], 'big')],
                                int.from_bytes(temp[4:8], 'big')))
                temp = temp[10 + int.from_bytes(temp[8:10], 'big'):]
            elif temp[:2] == b'\x00\x06':  # Type SOA
                ttl = int.from_bytes(temp[4:8], 'big')
                soa_data = temp[10:10 + int.from_bytes(temp[8:10], 'big')]
                answers.append((b'\x00\x06', addr, soa_data, ttl))
                temp = temp[10 + int.from_bytes(temp[8:10], 'big'):]
            elif temp[:2] == b'\x00\x0f':  # Type MX
                mx_data = temp[10: 10 + int.from_bytes(temp[8:10], 'big')]
                # Get rid of pointers:
                mx_data = mx_data[:2] + DNS.translate_domain(DNS.get_addr_from_bytes(mx_data[2:], data)[0])
                answers.append((temp[:2], addr, mx_data, int.from_bytes(temp[4:8], 'big')))
                temp = temp[10 + int.from_bytes(temp[8:10], 'big'):]
            elif temp[:2] == b'\x00\x21':  # Type SRV
                ttl = int.from_bytes(temp[4:8], 'big')
                srv_data = temp[10:10 + int.from_bytes(temp[8:10], 'big')]
                answers.append((b'\x00\x21', addr, srv_data, ttl))
                temp = temp[10 + int.from_bytes(temp[8:10], 'big'):]
            elif temp[:2] == b'\x00\x29':  # Type OPT
                answers.append((b'\x00\x29', addr, temp[2:10]))
                temp = temp[10:]
            elif temp[:2] == b'\x00\x41':  # Type HTTPS
                ttl = int.from_bytes(temp[4:8], 'big')
                https_data = temp[10:10 + int.from_bytes(temp[8:10], 'big')]
                answers.append((b'\x00\x41', addr, https_data, ttl))
                temp = temp[10 + int.from_bytes(temp[8:10], 'big'):]
            elif temp[:2] == b'\x00\x0c':  # Type PTR
                domain_name, num = DNS.get_addr_from_bytes(temp[10:], data)
                answers.append((b'\x00\x0c', addr, domain_name, int.from_bytes(temp[4:8], 'big')))
                temp = temp[11 + num:]
            else:
                print(temp[:2])
        return answers
