from socket import inet_ntoa
import socket
import scapy.all as s
from scapy.interfaces import get_working_if
from scapy.layers.inet import IP, TCP, UDP
from TcpConn import TcpSocket

s.verbose = 0


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
            print(num)
            if num == 0:
                break
            elif num == 0xc0:
                print('hi')
                rr = data[rr[0]:]
                print(rr)
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
        temp = data[20 + len(domain):]
        print(temp)
        while temp:
            addr, num = DNS.get_addr_from_bytes(temp, data)
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
    def get_next_server(answers, server, transc_id):
        for ans in answers:
            if ans[0] == b'\x00\x02':
                sock = TcpSocket(INTERFACE)
                sock.connect((server, 53))
                sock.send(TCP() / s.DNS(DNS.request_msg(transc_id.to_bytes(2, 'big'), ans[2], b'\x00\x01')))
                response = sock.read(1024)
                transc_id += 1
                lst = DNS.get_answers(ans[2], response)
                sock.close()

                #pkt = IP(dst=server) / UDP(sport=53, dport=53) / s.DNS(
                #    DNS.request_msg(transc_id.to_bytes(2, 'big'), ans[2], b'\x00\x01'))
                #response = s.sr1(pkt, iface=INTERFACE)
                #transc_id += 1
                #lst = DNS.get_answers(ans[2], bytes(response[UDP].payload))

                for ans1 in lst:
                    if ans1[0] == b'\x00\x01':
                        return ans1[2], transc_id
                    elif ans1[0] == b'\x00\x02':
                        return DNS.get_next_server(lst, server, transc_id)

    @staticmethod
    def find_addr(domain: str, dtype: bytes):
        transc_id = 0xd801
        server = DNS.get_root_server()

        for i in range(3):
            sock = TcpSocket(INTERFACE)
            sock.connect((server, 53))
            sock.send(TCP() / s.DNS(DNS.request_msg(transc_id.to_bytes(2, 'big'), domain, dtype)))
            response = sock.read(1024)
            transc_id += 1
            answers = DNS.get_answers(domain, response)
            sock.close()

            #pkt = IP(dst=server) / UDP(sport=55555, dport=53) / s.DNS(
            #    DNS.request_msg(transc_id.to_bytes(2, 'big'), domain, dtype))
            #response = s.sr1(pkt, iface=INTERFACE)
            #transc_id += 1
            #answers = DNS.get_answers(domain, bytes(response[UDP].payload))

            if domain in (i[1] for i in answers):
                result = []
                for ans in answers:
                    if ans[1] in (domain, *[i[1] for i in answers]):
                        result.append(ans)
                break
            else:
                server, transc_id = DNS.get_next_server(answers, server, transc_id)
        else:
            print('Could not find host')
            return

        transc_id += 1

        answers = []
        for auth in result:
            if auth[0] == b'\x00\x02':
                sock = TcpSocket(INTERFACE)
                sock.connect((server, 53))
                sock.send(TCP() / s.DNS(DNS.request_msg(transc_id.to_bytes(2, 'big'), domain, dtype)))
                response = sock.read(1024)
                transc_id += 1
                lst = DNS.get_answers(domain, bytes(response[TCP].payload))
                #sock.close()

                #pkt = IP(dst=auth[2]) / UDP(sport=53, dport=53) / s.DNS(
                #    DNS.request_msg(transc_id.to_bytes(2, 'big'), domain, dtype))
                #response = s.sr1(pkt, iface=INTERFACE)
                #transc_id += 1
                #lst = DNS.get_answers(domain, bytes(response[UDP].payload))

                return lst
            elif auth[0] in (dtype, b'\x00\x05'):
                answers.append(auth)
        return answers


INTERFACE = 'Ethernet 2'
DEFAULT_GATEWAY = '10.0.0.138'
print(DNS.find_addr('www.eranbi.net', b'\x00\x01'))
#DNS.get_root_server()
#print(DNS.get_answers('www.ynet.co.il', bytes.fromhex('0001808000010003000000000377777704796e657402636f02696c0000010001c00c000500010000002a001f0377777704796e657402636f05696c2d763107656467656b6579036e657400c02c000500010000008a001c0665313234373604647363620a616b616d616965646765036e657400c057000100010000001000045f64ce48')))

#pkt = IP(dst='198.41.0.4') / UDP(dport=53, sport=55555) / s.DNS(DNS.request_msg(b'\x00\x01', 'mikmak.co.il'))
#s.send(pkt, iface=INTERFACE)