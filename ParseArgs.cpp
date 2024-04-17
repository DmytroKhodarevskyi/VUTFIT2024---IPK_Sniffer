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
    {"ndp",               no_argument,       0, 'x'},
    {0, 0, 0, 0}
};

Parse::Parse(int argc, char** argv) :
    argc(argc), 
    argv(argv),
    tcp(false), udp(false),
    port_source(0), port_destination(0), port_both(0),
    icmp4(false), icmp6(false),
    arp(false), ndp(false), igmp(false), mld(false), 
    packets_cnt(1), 
    interface(""),
    
    display_interfaces(false),

    filter("")
    {}

void Parse::parseArguments() {
  int opt;
  int option_index = 0;
  opterr = 0;
  while ((opt = getopt_long(argc, argv, "i:s:d:p:tua46gmn:", long_options, &option_index)) != -1) {
    switch (opt) {
      case 'i':
        if (optarg != NULL) {
          interface = optarg;
        }
        else {
          interface = "";
        }
        break;
      case 's':
        port_source = std::stoi(optarg);
        filter.append("src port " + std::to_string(port_source));
        filter.append(" ");
        filter.append("or ");
        break;
      case 'd':
        port_destination = std::stoi(optarg);
        filter.append("dst port " + std::to_string(port_destination));
        break;
      case 't':
        tcp = true;
        break;
      case 'p':
        port_both = std::stoi(optarg);
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
      case 'x':
        ndp = true;
        break;
      case '?':
        interface = "";
        break;
    }
  }

  if ((interface.empty() && argc == 2) || (argc == 1)) {
      display_interfaces = true;
      return;
  }

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
    filter.append("(icmp6 and (ip6[40] == 133 or ip6[40] == 134 or ip6[40] == 135 or ip6[40] == 136 or ip6[40] == 137)) or ");
  if (igmp)
    filter.append("igmp or ");
  if (mld)
    filter.append("mld or ");

  filter = filter.substr(0, filter.size() - 4);
}

void Parse::constructFilter() {
  if (tcp) 
    filter.append("tcp and ");
  if (udp)
    filter.append("udp and ");

  if (port_both != 0 && (tcp || udp)) {
    filter.append("port " + std::to_string(port_both));
    filter.append(" or ");
  }
  if (port_source != 0 && (tcp || udp)) {
    filter.append("src port " + std::to_string(port_source));
    filter.append(" or ");
  }
  if (port_destination != 0 && (tcp || udp)) {
    filter.append("dst port " + std::to_string(port_destination));
    filter.append(" or ");
  }

  additionalFilter();

}

bool Parse::doPrintInterfaces() {
  return display_interfaces;
}

string Parse::getInterface() const {
  return interface;
}

unsigned int Parse::getPacketsCnt() const {
  return packets_cnt;
}

string Parse::getFilter() const {
  return filter;
}

