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
      /**
       * @brief Construct a new Parse object
      */
      Parse(int argc, char** argv);

      /**
       * @brief Parse the arguments
      */
      void parseArguments();

      /**
       * @brief Get the interface
       * @return Interface name string
      */
      string getInterface() const;

      /**
       * @brief Get the filter
       * @return Filter string
      */
      string getFilter() const;

      /**
       * @brief Get the packets count
       * @return packets count  
      */
      unsigned int getPacketsCnt() const;

      /**
       * @brief Get the interface print flag
       * @return display_interfaces flag
      */
      bool doPrintInterfaces();

  private:

    /**
     * @brief Construct the filter
    */
    void constructFilter();
    
    /**
     * @brief Additional filtering adding
    */
    void additionalFilter();

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
    string interface;

    bool display_interfaces;

    string filter;


};

#endif // PARSE_H