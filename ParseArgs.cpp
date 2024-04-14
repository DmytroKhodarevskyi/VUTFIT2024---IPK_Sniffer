#include "ParseArgs.hpp"

struct option long_options[] = {
    {"interface",         optional_argument, 0, 'i'},
    {"port-source",       required_argument, 0, 's'},
    {"port-destination",  required_argument, 0, 'd'},
    {"tcp",               no_argument,       0, 't'},
    {"udp",               no_argument,       0, 'u'},
    {"arp",               no_argument,       0, 'a'},
    {"icmp4",             no_argument,       0, '4'},
    {"icmp6",             no_argument,       0, '6'},
    {"igmp",              no_argument,       0, 'g'},
    {"mld",               no_argument,       0, 'm'},
    {"ndp",               no_argument,       0, 'n'},
    {0, 0, 0, 0}
};

Parse::Parse(int argc, char** argv) :
    argc(argc), 
    argv(argv),
    tcp(false), udp(false),
    port_source(0), port_destination(0), port_both(0),
    icmp4(false), icmp6(false),
    arp(false), ndp(false), igmp(false), mld(false), 
    packets_cnt(0), 
    interface(""),
    
    display_interfaces(false),
    filter_by_port(false),

    filter("")
    {}

void Parse::parseArguments() {
  int opt;
  int option_index = 0;
  while ((opt = getopt_long(argc, argv, "is:d:p:tua46gmn:", long_options, &option_index)) != -1) {
    switch (opt) {
      case 'i':
        interface = optarg ? optarg : "";
        break;
      case 's':
        port_source = std::stoi(optarg);
        filter_by_port = true;
        filter.append("src port " + std::to_string(port_source));
        filter.append(" ");
        filter.append("or ");
        break;
      case 'd':
        port_destination = std::stoi(optarg);
        filter_by_port = true;
        filter.append("dst port " + std::to_string(port_destination));
        break;
      case 't':
        tcp = true;
        break;
      case 'p':
        port_both = std::stoi(optarg);
        port_source = -1;
        port_destination = -1;
        filter_by_port = true;
        break;
      case 'u':
        udp = true;
        break;
      case 'a':
        arp = true;
        break;
      case '4':
        icmp4 = true;
        break;
      case '6':
        icmp6 = true;
        break;
      case 'g':
        igmp = true;
        break;
      case 'm':
        mld = true;
        break;
      case 'n':
        packets_cnt = std::stoi(optarg);
        break;
      case '?':
        // Handle unknown options or missing option arguments
        interface = "";
        break;
    }
  }

  if ((interface.empty() && argc == 2) || (argc == 1)) {
      // cerr << "No interface specified. Here is a list of available interfaces: ..." << std::endl;
      display_interfaces = true;
      return;
      // Code to list interfaces
  }

  // if (port_source == 0 && port_destination == 0) {
  //   filter_by_port = false;
  // }

  // if (icmp4 && ndp) {
  //   cerr << "Cannot filter by both ICMPv4 and NDP" << std::endl;
  //   exit(EXIT_FAILURE);
  // }

  // if (icmp6 && mld) {
  //   cerr << "Cannot filter by both ICMPv6 and ARP" << std::endl;
  //   exit(EXIT_FAILURE);
  // }
  
  constructFilter();

}

void Parse::additionalFilter() {
  if (icmp4) 
    filter.append("icmp or ");
  if (icmp6) 
    filter.append("icmp6 or ");
  if (arp) 
    filter.append("arp or ");
  if (ndp) 
    filter.append("ndp or ");
  if (igmp)
    filter.append("igmp or ");
  if (mld)
    filter.append("mld or ");

  filter = filter.substr(0, filter.size() - 4);
}

void Parse::constructFilter() {
  if (port_both != 0) {
    filter.append("port " + std::to_string(port_both));
    filter.append(" or ");
  }
  if (port_source != 0) {
    filter.append("src port " + std::to_string(port_source));
    filter.append(" or ");
  }
  if (port_destination != 0) {
    filter.append("dst port " + std::to_string(port_destination));
    filter.append(" or ");
  }

  additionalFilter();

}

bool Parse::doPrintInterfaces() {
  return display_interfaces;
}

bool Parse::doFilterByPort() {
  return filter_by_port;
}

string Parse::getInterface() const {
  return interface;
}

unsigned int Parse::getPortSource() const {
  return port_source;
}

unsigned int Parse::getPortDestination() const {
  return port_destination;
}

bool Parse::getArp() const {
  return arp;
}

bool Parse::getNdp() const {
  return ndp;
}

bool Parse::getIgmp() const {
  return igmp;
}

bool Parse::getMld() const {
  return mld;
}

bool Parse::getTcp() const {
  return tcp;
}

bool Parse::getUdp() const {
  return udp;
}

unsigned int Parse::getPacketsCnt() const {
  return packets_cnt;
}

