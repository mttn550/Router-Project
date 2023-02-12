import nmap
#nma = nmap.PortScannerAsync()
#def callback_result(host, scan_result):
#    print(host, scan_result)
#
#nma.scan(hosts='10.0.0.0/24', arguments='-sP', callback=callback_result)
#while nma.still_scanning():
#    print("Waiting >>>")
#    nma.wait(2)   # you can do whatever you want but I choose to wait after the end of the scan
import scapy_p0f
from scapy.layers.inet import Ether, IP

data = bytes.fromhex('0cb6d2e7e2c700e04c39931b08004500003496474000800600000a00000714498240d92901bb5b5ee1e0000000008002faf0a0b60000020405b40103030801010402')
scapy_p0f.prnp0f(Ether(data))
data2 = bytes.fromhex('450000347af94000800600000a00000536c86b2f155a01bb29a9864e000000008002faf0ac220000020405b40103030801010402')
print(scapy_p0f.p0f(IP(data2))[0][2])

#import numpy as np
#import time
#
#a = np.array(str(i) for i in range(100000))
#start = time.time()
#a.resize((100001,))
#a[-1] = '100001'
#print(a.__sizeof__())
#print(time.time() - start)
#
#b = list(str(i) for i in range(100000))
#start = time.time()
#b.append('100001')
#print(b.__sizeof__())
#print(time.time() - start)