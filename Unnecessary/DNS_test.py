import socket

def get_next_server(answers, server, transc_id, destination=''):
    for ans in answers:
        if ans[0] == b'\x00\x02':
            if destination == '':
                destination = ans[2]
            for ans1 in answers:
                if ans1[1] == destination and ans1[0] == b'\x00\x01':
                    return ans1[2], transc_id


def find_addr(domain: str, dtype: bytes, transc_id=0xd801):
    # server = DNS.get_root_server()
    server = '198.41.0.4'

    for i in range(3):
        answers = ask_server(server, domain, dtype, transc_id)
        transc_id += 1
        if domain in (i[1] for i in answers):  # I got the authoritative server.
            result = []
            for ans in answers:
                if ans[1] in (domain, *[i[2] for i in result]):
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
        if auth[0] == b'\x00\x01':
            if auth[1] == domain and dtype == b'\x00\x01':
                answers.append(auth)
            else:
                answers.append(*ask_server(auth[2], domain, dtype, transc_id))
                transc_id += 1
        elif auth[0] == b'\x00\x02':
            server = find_addr(auth[2], b'\x00\x01', transc_id)
            transc_id += 1
            answers.append(*ask_server(server, domain, dtype, transc_id))
        elif auth[0] in (dtype, b'\x00\x05'):
            answers.append(auth)
    return answers


def ask_server(server, domain, dtype, transc_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server, 53))
    sock.send(DNS.request_msg(transc_id.to_bytes(2, 'big'), domain, dtype))
    response = sock.recv(1500)
    sock.close()
    return DNS.get_answers(domain, response)