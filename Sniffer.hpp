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
    /**
     * @brief Construct a new Sniffer object with device
    */
    Sniffer(const string& device);

    /**
     * @brief Construct a new Sniffer object (only for listing interfaces)
    */
    Sniffer();

    /**
     * @brief Destroy the Sniffer object
    */
    ~Sniffer();

    /**
     * @brief Capture packets
     * @param num_packets Number of packets to capture
    */
    void capture(int num_packets);

    /**
     * @brief List active interfaces
    */
    void list_active_interfaces();

    /**
     * @brief Apply filter
     * @param filter Filter string
    */
    void applyFilter(const string& filter);

private:

    /**
     * @brief Callback function for packet capturing and processing
     * @param args Arguments
     * @param header Packet header
     * @param packet Packet
    */
    static void packetCallback(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

    string device_;
    pcap_t* handle_;
    bool list_interfaces_;
};

#endif // SNIFFER_H
