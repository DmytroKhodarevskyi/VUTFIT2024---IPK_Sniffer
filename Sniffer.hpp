#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <string>

using namespace std;

class Sniffer {
public:
    Sniffer(const string& device);
    Sniffer();
    ~Sniffer();
    void capture(int num_packets);
    void list_active_interfaces();
    void apply_filter(const string& filter);

private:
    static void packetCallback(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

    string device_;
    pcap_t* handle_;
    bool list_interfaces_;
};

#endif // SNIFFER_H
