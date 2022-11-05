import scapy.all as s
from scapy.layers.inet import IP, TCP
from random import randint
import socket, threading, time


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
           s.sniff(filter=f'src host {self.dst[0]} and dst host {self.src[0]}',
                   iface=self.iface, session=s.IPSession,
                   stop_filter=self.recv_handler), args=())
        self.sniff.start()

    def recv_handler(self, pkt):
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
            return False
        return True

    def read(self, buffsize):
        self._has_data.wait()
        self._has_data.clear()
        time.sleep(0.01)
        data = self._buffer[:buffsize]
        self._buffer = self._buffer[buffsize:]
        return data

    def close(self):
        fin = IP(src=self.src[0], dst=self.dst[0]) / TCP(sport=self.src[1], dport=self.dst[1], seq=self.seq, ack=self.ack, flags='FA')
        s.send(fin, iface=self.iface)  # Fin Ack
        self._stop = True
