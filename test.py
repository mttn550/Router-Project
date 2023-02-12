#from scapy.all import get_working_ifaces
#import pcap, time
#from psutil import net_if_addrs
#
##iface = netifaces.ifaddresses(netifaces.interfaces()[0])[2][0]
##print(iface)
##print(int(psutil.AF_LINK))
##print(next(iter(net_if_addrs().values()))[1])
#ip = next(iter(net_if_addrs().values()))[1].address
##print(next(i for i in s.get_working_ifaces() if i.ip == ip).network_name)
##print(psutil.net_if_addrs()['Ethernet 2'][0].address, psutil.net_if_addrs()['Ethernet 2'][1])
#iface_name = next(i for i in get_working_ifaces() if i.ip == ip).network_name
##gateway = netifaces.gateways()['default'][2][0]
#
#
#a = pcap.pcap(name=iface_name, immediate=True)     # construct pcap object
##pc.setfilter('icmp')  # filter out unwanted packets
##for timestamp, packet in pc:
##    print(packet)
##addr = lambda pkt, offset: '.'.join(str(ord(pkt[i])) for i in range(offset, offset + 4))
##for ts, pkt in sniffer:
##    print('%d\tSRC %-16s\tDST %-16s' % (ts, addr(pkt, sniffer.dloff + 12), addr(pkt, sniffer.dloff + 16)))
#
##data = bytes.fromhex('0cb6d2e7e2c700e04c39931b08004500003c8a6b0000800100000a0000060a00008a08004d52000100096162636465666768696a6b6c6d6e6f7071727374757677616263646566676869')
#start = time.time()
#data = b'\xff'* 1514
#a.sendpacket(data)
#print(time.time() - start)
#import time
#start = time.time()
#a = {}
#for i in range(10**6):
#    a[str(i)] = '1'
#print(a.__sizeof__())
#print(time.time() - start)
#start = time.time()
#b = b''
#for i in range(10**6):
#    b += str(i).encode() + b'1'
#print(b.__sizeof__())
#print(time.time() - start)
#

#from Base.Sniffer import Sniffer
#print(1)
#a = Sniffer(iface='\\Device\\NPF_{1B3DC0C9-7A0B-4CCF-B611-8DDBD82AB46F}')
#a.start()
from tkinter import *
from  tkinter import ttk


ws  = Tk()
ws.title('PythonGuides')
ws.geometry('500x500')
ws['bg'] = '#AC99F2'

game_frame = Frame(ws)
game_frame.pack()

my_game = ttk.Treeview(game_frame)

my_game['columns'] = ('player_id', 'player_name', 'player_Rank', 'player_states', 'player_city')

my_game.column("#0", width=0,  stretch=NO)
my_game.column("player_id",anchor=CENTER, width=80)
my_game.column("player_name",anchor=CENTER,width=80)
my_game.column("player_Rank",anchor=CENTER,width=80)
my_game.column("player_states",anchor=CENTER,width=80)
my_game.column("player_city",anchor=CENTER,width=80)

my_game.heading("#0",text="",anchor=CENTER)
my_game.heading("player_id",text="Id",anchor=CENTER)
my_game.heading("player_name",text="Name",anchor=CENTER)
my_game.heading("player_Rank",text="Rank",anchor=CENTER)
my_game.heading("player_states",text="States",anchor=CENTER)
my_game.heading("player_city",text="States",anchor=CENTER)

my_game.insert(parent='',index='end',iid=0,text='',
values=('1','Ninja','101','Oklahoma', 'Moore'))
my_game.insert(parent='',index='end',iid=1,text='',
values=('2','Ranger','102','Wisconsin', 'Green Bay'))
my_game.insert(parent='',index='end',iid=2,text='',
values=('3','Deamon','103', 'California', 'Placentia'))
my_game.insert(parent='',index='end',iid=3,text='',
values=('4','Dragon','104','New York' , 'White Plains'))
my_game.insert(parent='',index='end',iid=4,text='',
values=('5','CrissCross','105','California', 'San Diego'))
my_game.insert(parent='',index='end',iid=5,text='',
values=('6','ZaqueriBlack','106','Wisconsin' , 'TONY'))

my_game.pack()

ws.mainloop()
