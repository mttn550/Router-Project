from socket import inet_aton, inet_ntoa
import scapy.all as s

s.Ether(dst=b'\xff\xff\xff\xff\xff\xff').show()