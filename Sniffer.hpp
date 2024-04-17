#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <string>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <typeinfo>
#include <cstring>
#include <bitset> 
#include <math.h>
#include <time.h>


#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>

using namespace std;

class Sniffer {
public:
    Sniffer(const string& device);
    Sniffer();
    ~Sniffer();
    void capture(int num_packets);
    void list_active_interfaces();
    void applyFilter(const string& filter);

private:
    static void packetCallback(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

    string device_;
    pcap_t* handle_;
    bool list_interfaces_;
};

#endif // SNIFFER_H
