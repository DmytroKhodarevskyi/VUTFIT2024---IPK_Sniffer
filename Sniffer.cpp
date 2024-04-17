#include "Sniffer.hpp"
#include <iostream>

Sniffer::Sniffer(const string& device) : device_(device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Could not open device " << device << ": " << errbuf << endl;
        exit(1);
    }
    handle_ = handle;
    list_interfaces_ = false;
}

Sniffer::Sniffer() {
    list_interfaces_ = true;
}

Sniffer::~Sniffer() {
    if (!list_interfaces_ && handle_ != nullptr) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void Sniffer::list_active_interfaces() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    // Print the list
    for (device = alldevs; device != NULL; device = device->next) {
        if (device->name)
          cout << device->name << endl;
    }

    // Free the device list
    if (alldevs != NULL)
      pcap_freealldevs(alldevs);
}

void Sniffer::applyFilter(const string& filter) {
  
    auto filter_ = filter;
    if (filter_.empty()) {
    filter_ = "";
    cerr << "No filtering." << endl << endl;
    } else {
    cerr << "Filter: " << filter_ << endl << endl;
    }

    struct bpf_program fp;
    if (pcap_compile(handle_, &fp, filter_.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Could not parse filter " << filter_ << ": " << pcap_geterr(handle_) << endl;
        exit(1);
    }
    if (pcap_setfilter(handle_, &fp) == -1) {
        cerr << "Could not install filter " << filter_ << ": " << pcap_geterr(handle_) << endl;
        exit(1);
    }
}


void Sniffer::capture(int num_packets) {
    pcap_loop(handle_, num_packets, packetCallback, nullptr);
}

void Sniffer::packetCallback(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {

    // construct the timestamp
    char timeBuffer[20];
    char timezoneBuffer[6];
    
    struct tm* timeInfo = localtime(&header->ts.tv_sec); 
    strftime(timeBuffer, sizeof(timeBuffer), "%FT%T", timeInfo); 
    int milliseconds = lrint(header->ts.tv_usec / 1000.0); // round to nearest millisecond
    strftime(timezoneBuffer, sizeof(timezoneBuffer), "%z", timeInfo); // timezone
    
    // converting timezone offset to RFC3339 format
    string timezone = timezoneBuffer; // e.g. +300 to +03:00, +1000 to +10:00
    (timezone.length() == 4) ? (timezone.insert(1, 1, '0'), timezone.insert(3, 1, ':')) : (timezone.insert(3, 1, ':'));

    struct ether_header* eth = (struct ether_header*)packet;
    int offset = sizeof(struct ether_header);

    cout << "Timestamp: " << timeBuffer << "." << milliseconds << timezone << endl;
    cout << "src MAC: ";
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->ether_shost[i]);
        if (i < 5) {
            cout << ":";
        }
    }
    cout << endl;

    cout << "dst MAC: ";
    for (int i = 6; i < 12; i++) {
        printf("%02x", eth->ether_dhost[i]);
        if (i < 11) {
            cout << ":";
        }
    }
    cout << endl;

    cout << "frame length: " << header->len << " bytes" << endl;

    int eth_type = ntohs(eth->ether_type);
    
    if (eth_type == ETHERTYPE_IP) { // ICMPv4
        struct  ip* ip = (struct ip*)(packet + offset);

        offset += sizeof(struct ip);

        char srcICMPv4[INET_ADDRSTRLEN];
        char dstICMPv4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->ip_src, srcICMPv4, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->ip_dst, dstICMPv4, INET_ADDRSTRLEN);
        cout << "src IP: " << srcICMPv4 << endl;
        cout << "dst IP: " << dstICMPv4 << endl;

        auto protocol = ip->ip_p;

        if (protocol == IPPROTO_ICMP) {
            struct tcphdr* icmp = (struct tcphdr*)(packet + offset);
            offset += sizeof(icmp);
        }

        if (protocol == IPPROTO_UDP) {
            struct udphdr* udp = (struct udphdr*)(packet + offset);

            cout << "src port: " << ntohs(udp->uh_sport) << endl;
            cout << "dst port: " << ntohs(udp->uh_dport) << endl;

            offset += sizeof(struct udphdr);
        }

        if (protocol == IPPROTO_TCP) {
            struct tcphdr* tcp = (struct tcphdr*)(packet + offset);

            cout << "src port: " << ntohs(tcp->th_sport) << endl;
            cout << "dst port: " << ntohs(tcp->th_dport) << endl;

            offset += sizeof(struct tcphdr);
        }
    }

    if (eth_type == ETHERTYPE_IPV6) { // ICMPv6
        struct ip6_hdr* ip6 = (struct ip6_hdr*)(packet + offset);

        offset += sizeof(struct ip6_hdr);

        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

        char srcIP[INET6_ADDRSTRLEN];
        char dstIP[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, srcIP, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6->ip6_dst, dstIP, INET6_ADDRSTRLEN);
        cout << "src IP: " << srcIP << endl;
        cout << "dst IP: " << dstIP << endl;

        auto protocol = ip6->ip6_nxt;

        if (protocol == IPPROTO_ICMPV6) {
            struct icmp6_hdr* icmp6 = (struct icmp6_hdr*)(packet + offset);
            offset += sizeof(icmp6);
        }

        if (protocol == IPPROTO_UDP) {
            struct udphdr* udp = (struct udphdr*)(packet + offset);

            cout << "src port: " << ntohs(udp->uh_sport) << endl;
            cout << "dst port: " << ntohs(udp->uh_dport) << endl;

            offset += sizeof(struct udphdr);
        }

        if (protocol == IPPROTO_TCP) {
            struct tcphdr* tcp = (struct tcphdr*)(packet + offset);

            cout << "src port: " << ntohs(tcp->th_sport) << endl;
            cout << "dst port: " << ntohs(tcp->th_dport) << endl;

            offset += sizeof(struct tcphdr);
        }
    }

    if (eth_type == ETHERTYPE_ARP) {
        struct ether_arp* arp = (struct ether_arp*)(packet + offset);

        offset += sizeof(struct ether_arp);

        char srcARP[INET_ADDRSTRLEN];
        char dstARP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->arp_spa, srcARP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp->arp_tpa, dstARP, INET_ADDRSTRLEN);
        cout << "src IP: " << srcARP << endl;
        cout << "dst IP: " << dstARP << endl;
    }

    cout << "byte_offset: " << offset << endl;

    string ascii_buffer = "";

    // print the packet
    unsigned int i = 0;
    for ( ; i < header->len; i++) {
        
        if (i % 16 == 0) {
            if (ascii_buffer.length() >= 8) {
                ascii_buffer.insert(8, " ");
            }
            cout << ascii_buffer;
            ascii_buffer.clear();
            cout << endl;
            printf("0x%.4x:  ", i);
        }
        ascii_buffer += (isprint(packet[i]) ? packet[i] : '.');
        printf("%02x ", packet[i]);
    }

    int spaces_left = 16 - (i % 16);
    for (int j = 0; j < spaces_left; j++) {
        cout << "   ";
    }

    if (ascii_buffer.length() >= 8) {
        ascii_buffer.insert(8, " ");
    }
    cout << ascii_buffer;


    cout << endl << endl;
}
