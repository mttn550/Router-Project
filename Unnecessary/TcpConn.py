import scapy.all as s
from scapy.layers.inet import IP, TCP
from random import randint
import socket, threading


s.verbose = 0

class TcpSocket:

    def __init__(self, iface=s.get_working_if()):
        self.src = ('', -1)
        self.dst = ('', -1)
        self.seq = -1
        self.ack = -1
        self.iface = iface
        self._buffer = b''
        self._has_data = threading.Event()
        self._stop = False

    def bind(self, src):
        self.src = src

    def connect(self, dst):
        if self.src == ('', -1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', 0))
            self.src = sock.getsockname()
            sock.close()
        self.dst = dst
        self.seq = randint(0, 2**32)
        syn = IP(dst=dst[0]) / TCP(sport=self.src[1], dport=dst[1], seq=self.seq, flags='S')
        synack = s.sr1(syn, iface=self.iface)
        if synack[TCP].flags == 'SA':
            self.src = (synack[IP].dst, self.src[1])
            self.ack = synack[TCP].seq
            self.seq += 1
            ack = IP(src=self.src[0], dst=dst[0]) / TCP(sport=self.src[1], dport=dst[1], seq=self.seq, ack=self.ack, flags='A')
            s.send(ack, iface=self.iface)
            self._recv()
        else:
            self.connect(self.dst)

    def send(self, pkt):
        pkt[TCP].seq = self.seq
        pkt[TCP].ack = self.ack
        pkt[TCP].sport = self.src[1]
        pkt[TCP].dport = self.dst[1]
        pkt[TCP].flags = 'A'
        s.send(IP(src=self.src[0], dst=self.dst[0]) / pkt, iface=self.iface)
        self.seq += len(pkt[TCP].payload)

    def _recv(self):
        self.sniff = threading.Thread(target=lambda:
           s.sniff(filter=f'dst host {self.src[0]} and src host {self.dst[0]}',
                   iface=self.iface, session=s.IPSession,
                   prn=self.recv_handler, stop_filter=lambda pkt: self._stop), args=())
        self.sniff.start()

    def recv_handler(self, pkt):
        if self._stop or pkt[IP].src != self.dst[0]: return
        if not (pkt.haslayer(TCP) and pkt[TCP].sport == self.dst[1] and pkt[TCP].dport == self.src[1]):
            return False
        if (bytes(pkt[TCP].payload) in (b'\x00\x00\x00\x00\x00\x00', b'') and pkt[TCP].flags == 'A') or \
           'S' in pkt[TCP].flags:
            return False
        if 'R' in pkt[TCP].flags:
            self.connect(self.dst)
            return True
        if 'F' in pkt[TCP].flags:
            self.close()
        self._buffer += bytes(pkt[TCP].payload)
        self.ack = pkt[TCP].seq + len(pkt[TCP].payload)
        if not self._stop:
            ack_pkt = IP(src=self.src[0], dst=self.dst[0]) / TCP(sport=self.src[1], dport=self.dst[1], seq=self.seq, ack=self.ack, flags='A')
            s.send(ack_pkt, iface=self.iface)
            self._has_data.set()

    def read(self, buffsize, timeout=None):
        if not self._has_data.wait(timeout): return b''
        self._has_data.clear()
        data = self._buffer[:buffsize]
        self._buffer = self._buffer[buffsize:]
        return data

    def close(self):
        fin = IP(src=self.src[0], dst=self.dst[0]) / TCP(sport=self.src[1], dport=self.dst[1], seq=self.seq, ack=self.ack, flags='FA')
        s.sr1(fin, iface=self.iface)  # Fin Ack
        s.send(IP(src=self.src[0], dst=self.dst[0]) / TCP(sport=self.src[1], dport=self.dst[1], seq=self.seq + 1, ack=self.ack + 1, flags='A'))
        self._stop = True


def request_msg(transc_id: bytes, domain: str, dtype: bytes):
    data = transc_id + b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    if domain != '':
        for i in domain.split('.'):
            data += len(i).to_bytes(1, 'big') + i.encode('utf-8')
    data += b'\x00' + dtype + b'\x00\x01'
    return len(data).to_bytes(2, 'big') + data


#sock = TcpSocket('Ethernet 2')
#sock.connect(('198.41.0.4', 53))
#sock.send(TCP() / s.DNS(request_msg((1).to_bytes(2, 'big'), 'www.eranbi.net', b'\x00\x01')))
#response = sock.read(1500)
#response += sock.read(1500, 0.5)
#print(response)
#sock.close()
#del sock

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('198.41.0.4', 53))
sock.send(request_msg((1).to_bytes(2, 'big'), 'www.eranbi.net', b'\x00\x01'))
data = sock.recv(1500)
print(data)
sock.close()