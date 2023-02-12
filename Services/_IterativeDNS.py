from socket import inet_ntoa
import socket
import scapy.all as s
from scapy.layers.inet import IP, UDP


class DNS:

    @staticmethod
    def request_msg(transc_id: bytes, domain: str, dtype: bytes):
        data = transc_id + b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        if domain != '':
            for i in domain.split('.'):
                data += len(i).to_bytes(1, 'big') + i.encode('utf-8')
        data += b'\x00' + dtype + b'\x00\x01'
        return len(data).to_bytes(2, 'big') + data

    @staticmethod
    def response_msg(transc_id: bytes, domain: str, answers: list):
        data = transc_id + b'\x81\x80\x00\x01' + len(answers).to_bytes(2, 'big') + \
               b'\x00\x00\x00\x00' + domain.encode('utf-8') + b'\x00\x01\x00\x01'
        answer_format = lambda ans_type, ans_ttl, ans_length, ans_data: \
            b'\xc0\x0c' + type + b'\x00\x01' + ttl.tobytes(4, 'big') + length.tobytes(2, 'big') + data
        for type, ttl, length, data in answers:
            data += answer_format(type, ttl, length, data)
        return data

    @staticmethod
    def get_addr_from_bytes(rr: bytes, data: bytes):
        addr = ''
        sum = 0; ref = False
        while True:
            num, rr = rr[0], rr[1:]
            if num == 0:
                break
            elif bin(num)[2:].zfill(8)[:4] == bin(0xc0)[2:].zfill(8)[:4]:
                index = int(bin(num-0xc0)[2:].zfill(8) + bin(rr[0])[2:].zfill(8), 2)
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
        data = data[2:]
        temp = data[18 + len(domain):]
        while temp:
            addr, num = DNS.get_addr_from_bytes(temp, data)
            if addr == '':
                addr = '<Root>'
            temp = temp[num + 1:]
            if temp[:2] == b'\x00\x02':  # Type NS
                ns_addr, num = DNS.get_addr_from_bytes(temp[10:], data)
                answers.append((b'\x00\x02', addr, ns_addr, temp[4:8]))
                temp = temp[11 + num:]
            elif temp[:2] == b'\x00\x01':  # Type A
                answers.append((temp[:2], addr, inet_ntoa(temp[10: 14]), temp[4:8]))
                temp = temp[14:]
            elif temp[:2] == b'\x00\x05':  # Type CNAME
                cname_addr, num = DNS.get_addr_from_bytes(temp[10:], data)
                answers.append((temp[:2], addr, cname_addr, temp[4:8]))
                temp = temp[11 + num:]
            elif temp[:2] == b'\x00\x1c':  # Type AAAA
                answers.append((temp[:2], addr, temp[10: 10 + int.from_bytes(temp[8:10], 'big')], temp[4:8]))
                temp = temp[10 + int.from_bytes(temp[8:10], 'big'):]
            else:
                print(temp[:2])
        print(answers)
        return answers

    @staticmethod
    def get_root_server():
        pkt = IP(dst=DEFAULT_GATEWAY) / UDP(sport=55555, dport=53) / s.DNS(
            DNS.request_msg((1).to_bytes(2, 'big'), '', b'\x00\x01')[2:])
        response = s.sr1(pkt, iface=INTERFACE)
        data = bytes(response[UDP].payload)
        num = int.from_bytes(data[26:28], 'big')
        addr = DNS.get_addr_from_bytes(data[28: 28 + num], data)[0]

        pkt = IP(dst=DEFAULT_GATEWAY) / UDP(sport=55555, dport=53) / s.DNS(
            DNS.request_msg((2).to_bytes(2, 'big'), addr, b'\x00\x01')[2:])
        response = s.sr1(pkt, iface=INTERFACE)
        lst = DNS.get_answers(addr, b'\x00\x00' + bytes(response[UDP].payload))
        server = None
        for ans1 in lst:
            if ans1[0] == b'\x00\x01':
                server = ans1[2]
                break
        return server

    @staticmethod
    def ask_server(server, domain, dtype, transc_id):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server, 53))
        sock.send(DNS.request_msg(transc_id.to_bytes(2, 'big'), domain, dtype))
        response = sock.recv(1500)
        sock.close()
        return DNS.get_answers(domain, response)

    @staticmethod
    def get_next_server(answers, transc_id, destination, dtype):
        for ans in answers:
            if ans[0] == b'\x00\x02':
                for ans1 in answers:
                    if ans1[1] == destination and ans1[0] == dtype:
                        return None
                    if ans1[1] == ans[2] and ans1[0] == b'\x00\x01':
                        return ans1[2], transc_id

    @staticmethod
    def find_addr(domain: str, dtype: bytes, transc_id=0xd801):
        # server = DNS.get_root_server()
        server = '198.41.0.4'

        for i in range(4):
            answers = DNS.ask_server(server, domain, dtype, transc_id)
            transc_id += 1
            next_server = DNS.get_next_server(answers, transc_id, domain, dtype)
            if next_server is None:
                if any(i[1].count('.') >= 1 and domain.endswith(i[1]) for i in answers):  # I got the authoritative server.
                    result = []
                    for ans in answers:
                        if (ans[1].count('.') >= 1 and domain.endswith(ans[1])) or \
                                ans[1] in (i[2] for i in result):
                            result.append(ans)
                    break
                elif domain in (i[1] for i in answers):
                    result = []
                    for ans in answers:
                        if ans[1] in (domain, *[i[2] for i in result]):
                            result.append(ans)
                    break
                else:
                    server = DNS.ask_server(
                        server, next(i[2] for i in answers if i[0] == b'\x00\x02'), b'\x00\x01', transc_id)
                    transc_id += 1
            else:
                server, transc_id = next_server
        else:
            print('Could not find host')
            return

        transc_id += 1

        answers = []
        for auth in result:
            if auth[0] == b'\x00\x01':
                if auth[1] == domain and dtype == b'\x00\x01':
                    answers.append(auth)
                else:
                    answers.append(DNS.ask_server(auth[2], domain, dtype, transc_id))
            elif auth[0] == dtype:
                answers.append(auth)
            elif auth[0] == b'\x00\x02' and auth[2] not in (i[1] for i in result):
                server = next(i[2] for i in DNS.find_addr(auth[2], b'\x00\x01', transc_id) if i[0] == b'\x00\x01')
                transc_id += 1
                return DNS.ask_server(server, domain, dtype, transc_id)
            elif auth[0] in (dtype, b'\x00\x05'):
                answers.append(auth)
        return answers


INTERFACE = 'Ethernet 2'
DEFAULT_GATEWAY = s.conf.route.route('0.0.0.0')[2]

print(DNS.find_addr('eranbi.net', b'\x00\x01'))