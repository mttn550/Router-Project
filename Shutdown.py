from IGMP import IGMPv3
import scapy.all as s


def shutdown(mac, out_addr):
    leave_pkt = s.Ether(src=mac) / s.IP(src=out_addr, dst='224.0.0.9', proto=2) / IGMPv3.leave()
    s.sendp(leave_pkt)