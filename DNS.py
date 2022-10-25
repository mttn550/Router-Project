from socket import inet_ntoa
from scapy.interfaces import get_working_if


class DNS:

    @staticmethod
    def request_msg(transc_id: bytes, domain: str, dtype: bytes):
        data = transc_id + b'\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00'
        if domain != '':
            for i in domain.split('.'):
                data += len(i).to_bytes(1, 'big') + i.encode('utf-8')
        data += b'\x00' + dtype + b'\x00\x01'
        return data

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
<<<<<<< Updated upstream
            num, rr = rr[0], rr[1:]
            print(num)
            if num == 0xc0:
                rr = data[rr[0]:]
                ref = True; sum += 1
                continue
            if num == 0:
                break
            print(rr[:num], end='\n\n')
            addr += rr[:num].decode() + '.'
            if not ref: sum += num + 1
            rr = rr[num:]
        return addr[:-1], sum
=======
            #print(rr)
            num, rr = rr[0], rr[1:]
            if num == 0:
                break
            elif num == 0xc0:
                rr = data[rr[0]:]
                ref = True; sum += 2
                continue
            #print(num)
            #print(rr[:num])
            addr += rr[:num].decode() + '.'
            if not ref: sum += num + 1
            rr = rr[num:]
        return addr[:-1], sum - 1
>>>>>>> Stashed changes

    @staticmethod
    def get_answers(domain: str, data: bytes):
        answers = []
        temp = data[18 + len(domain):]
<<<<<<< Updated upstream
        while temp:
            addr, num = DNS.get_addr_from_bytes(temp, data)
            #print(addr)
            temp = temp[num + 1:]
            if temp[:2] == b'\x00\x02':  # Type NS
                ns_addr, num = DNS.get_addr_from_bytes(temp[10:], data)
                #print('ns_addr: ' + ns_addr + '\n')
                answers.append((b'\x00\x02', addr, ns_addr, temp[4:8]))
=======
        #print(temp)
        while temp:
            #print(temp)
            addr, num = DNS.get_addr_from_bytes(temp, data)
            #print(addr)
            #print(num)
            temp = temp[num + 1:]
            #print(temp)
            if temp[:2] == b'\x00\x02':  # Type NS
                ns_addr, num = DNS.get_addr_from_bytes(temp[10:], data)
                print('ns_addr: ' + ns_addr + '\n')
                answers.append((b'\x00\x02', addr, ns_addr, temp[4:8]))
                print(num)
                print(temp)
                print(temp[:11+num])
>>>>>>> Stashed changes
                temp = temp[11 + num:]
            else:
                answers.append((temp[:2], addr, inet_ntoa(temp[10: 14]), temp[4:8]))
                temp = temp[14:]
        return answers

    @staticmethod
    def get_root_server():
        pkt = s.IP(dst='172.20.10.1') / s.UDP(sport=53, dport=53) / s.DNS(
            DNS.request_msg((1).to_bytes(2, 'big'), '', b'\x00\x01'))
        response = s.sr1(pkt, iface=INTERFACE)
        data = bytes(response[s.UDP].payload)
        num = int.from_bytes(data[26:28], 'big')
        addr = DNS.get_addr_from_bytes(data[28: 28 + num], data)[0]

        pkt = s.IP(dst='172.20.10.1') / s.UDP(sport=53, dport=53) / s.DNS(
            DNS.request_msg((2).to_bytes(2, 'big'), addr, b'\x00\x01'))
        response = s.sr1(pkt, iface=INTERFACE)
        lst = DNS.get_answers(addr, bytes(response[s.UDP].payload))
        server = None
        for ans1 in lst:
            if ans1[0] == b'\x00\x01':
                server = ans1[2]
                break
        return server

    @staticmethod
<<<<<<< Updated upstream
=======
    def get_next_server(answers, server, transc_id):
        for ans in answers:
            if ans[0] == b'\x00\x02':
                pkt = s.IP(dst=server) / s.UDP(sport=53, dport=53) / s.DNS(
                    DNS.request_msg(transc_id.to_bytes(2, 'big'), ans[2], b'\x00\x01'))
                response = s.sr1(pkt, iface=INTERFACE)
                transc_id += 1
                lst = DNS.get_answers(ans[2], bytes(response[s.UDP].payload))
                for ans1 in lst:
                    if ans1[0] == b'\x00\x01':
                        return ans1[2], transc_id
                    elif ans1[0] == b'\x00\x02':
                        return DNS.get_next_server(lst, server, transc_id)

    @staticmethod
>>>>>>> Stashed changes
    def find_addr(domain: str, dtype: bytes):
        transc_id = 1
        server = DNS.get_root_server()

        for i in range(3):
            pkt = s.IP(dst=server) / s.UDP(sport=53, dport=53) / s.DNS(
                DNS.request_msg(transc_id.to_bytes(2, 'big'), domain, dtype))
            response = s.sr1(pkt, iface=INTERFACE)
            transc_id += 1
            answers = DNS.get_answers(domain, bytes(response[s.UDP].payload))
<<<<<<< Updated upstream
=======
            print(answers)
>>>>>>> Stashed changes
            if domain in (i[1] for i in answers):
                result = []
                for ans in answers:
                    if ans[1] == domain:
                        result.append(ans)
                break
            else:
<<<<<<< Updated upstream
                for ans in answers:
                    if ans[0] == b'\x00\x02':
                        pkt = s.IP(dst=server) / s.UDP(sport=53, dport=53) / s.DNS(
                            DNS.request_msg(transc_id.to_bytes(2, 'big'), ans[2], b'\x00\x01'))
                        response = s.sr1(pkt, iface=INTERFACE)
                        transc_id += 1
                        lst = DNS.get_answers(ans[2], bytes(response[s.UDP].payload))
                        for ans1 in lst:
                            if ans1[0] == b'\x00\x01':
                                server = ans1[2]
                                break
                        else:
                            continue
                        break
                else:
                    print('The answers were not useful.')
                    return
=======
                server, transc_id = DNS.get_next_server(answers, server, transc_id)
>>>>>>> Stashed changes
        else:
            print('Could not find host')
            return

        transc_id += 1

        answers = []
        for auth in result:
            if auth[0] == b'\x00\x02':
                pkt = s.IP(dst=auth[2]) / s.UDP(sport=53, dport=53) / s.DNS(
                    DNS.request_msg(transc_id.to_bytes(2, 'big'), domain, dtype))
                response = s.sr1(pkt, iface=INTERFACE)
                transc_id += 1
                lst = DNS.get_answers(domain, bytes(response[s.UDP].payload))
                for ans in lst:
                    if ans[0] == dtype:
                        answers.append(ans[2])
                if answers:
                    return answers
            elif auth[0] == dtype:
                answers.append(auth[2])
            if answers:
                return answers


import scapy.all as s

INTERFACE = get_working_if()
<<<<<<< Updated upstream
print(DNS.find_addr('www.eranbi.net', b'\x00\x01'))
#DNS.get_root_server()
#print(DNS.get_answers('e.gtld-servers.net', bytes.fromhex('00028080000100010000000001650c67746c642d73657276657273036e65740000010001c00c000100010000ea570004c00c5e1e')))
=======
#print(DNS.find_addr('www.eranbi.net', b'\x00\x01'))
#DNS.get_root_server()
print(DNS.get_answers('www.eranbi.net', bytes.fromhex('0001821000010000000d000b03777777066572616e6269036e65740000010001c017000200010002a300001101650c67746c642d73657276657273c017c017000200010002a30000040166c02ec017000200010002a3000004016dc02ec017000200010002a30000040169c02ec017000200010002a3000004016ac02ec017000200010002a30000040162c02ec017000200010002a30000040161c02ec017000200010002a30000040163c02ec017000200010002a3000004016bc02ec017000200010002a30000040168c02ec017000200010002a3000004016cc02ec017000200010002a30000040167c02ec017000200010002a30000040164c02ec02c000100010002a3000004c00c5e1ec02c001c00010002a3000010200105021ca100000000000000000030c049000100010002a3000004c023331ec049001c00010002a300001020010503d41400000000000000000030c059000100010002a3000004c037531ec059001c00010002a300001020010501b1f900000000000000000030c069000100010002a3000004c02bac1ec069001c00010002a30000102001050339c100000000000000000030c079000100010002a3000004c0304f1ec079001c00010002a300001020010502709400000000000000000030c089000100010002a3000004c0210e1e')))
>>>>>>> Stashed changes
#pkt = s.IP(dst='198.41.0.4') / s.UDP(dport=53, sport=55555) / s.DNS(DNS.request_msg(b'\x00\x01', 'mikmak.co.il'))
#s.send(pkt, iface=INTERFACE)