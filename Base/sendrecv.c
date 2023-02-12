#include <npcap/pcap.h>

void send(u_char pkt[], char name[])
{
    char a[1];
    pcap_t *iface;
    iface = pcap_open(name, // name of the device
            100, // portion of the packet to capture
            PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
            1000, // read timeout
            NULL, // authentication on the remote machine
            a // error buffer
            );
    pcap_sendpacket(iface, pkt, sizeof(pkt));
}