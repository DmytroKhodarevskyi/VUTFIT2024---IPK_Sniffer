#ifndef PARSE_H
#define PARSE_H


#include <iostream>
#include <cstdlib>
#include <getopt.h>
#include <unistd.h>
#include <cstdlib>
#include <vector>

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

extern struct option long_options[];


class Parse {

  public:
      Parse(int argc, char** argv);

      void parseArguments();

      string getInterface() const;
      unsigned int getPortSource() const;
      unsigned int getPortDestination() const;
      bool getArp() const;
      bool getNdp() const;
      bool getIgmp() const;
      bool getMld() const;
      bool getTcp() const;
      bool getUdp() const;
      unsigned int getPacketsCnt() const;
      string getFilter() const;

      bool doPrintInterfaces();
      bool doFilterByPort();

      void constructFilter();


  private:

    int argc;
    char** argv;

    bool tcp;
    bool udp;

    int port_source;
    int port_destination;
    int port_both;

    bool icmp4;
    bool icmp6;

    bool arp;
    bool ndp;
    bool igmp;
    bool mld;
    unsigned int packets_cnt;
    // vector<string> interfaces;
    string interface;

    bool display_interfaces;
    bool filter_by_port;

    string filter;


    // static struct option long_options[] = {
    //   {"interface",         optional_argument, 0, 'i'},
    //   {"port-source",       required_argument, 0, 's'},
    //   {"port-destination",  required_argument, 0, 'd'},
    //   {"tcp",               no_argument,       0, 't'},
    //   {"udp",               no_argument,       0, 'u'},
    //   {"arp",               no_argument,       0, 'a'},
    //   {"icmp4",             no_argument,       0, '4'},
    //   {"icmp6",             no_argument,       0, '6'},
    //   {"igmp",              no_argument,       0, 'g'},
    //   {"mld",               no_argument,       0, 'm'},
    //   {"ndp",               no_argument,       0, 'n'},
    //   {0, 0, 0, 0}
    // };



};

#endif // PARSE_H