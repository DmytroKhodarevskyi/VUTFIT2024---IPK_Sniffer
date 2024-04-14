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
    // list_active_interfaces();
  // Default constructor used to list active interfaces
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
    // printf("Available network devices:\n");
    for (device = alldevs; device != NULL; device = device->next) {
        // printf("%d. %s", ++device_count, device->name);
        if (device->name)
          cout << device->name << endl;
        // if (device->description)
            // printf(" (%s)\n", device->description);
        // else
            // printf(" (No description available)\n");
    }

    // Free the device list
    if (alldevs != NULL)
      pcap_freealldevs(alldevs);
}

void Sniffer::applyFilter(const string& filter) {
    struct bpf_program fp;
    if (pcap_compile(handle_, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Could not parse filter " << filter << ": " << pcap_geterr(handle_) << endl;
        exit(1);
    }
    if (pcap_setfilter(handle_, &fp) == -1) {
        cerr << "Could not install filter " << filter << ": " << pcap_geterr(handle_) << endl;
        exit(1);
    }
}


void Sniffer::capture(int num_packets) {
    pcap_loop(handle_, num_packets, packetCallback, nullptr);
}

void Sniffer::packetCallback(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    std::cout << "Captured a packet!" << std::endl;
    // Additional packet processing could go here
}
