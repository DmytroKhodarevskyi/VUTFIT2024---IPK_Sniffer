#include "Sniffer.hpp"
#include "ParseArgs.hpp"

using namespace std;

int main(int argc, char** argv) {
    Parse parse = Parse(argc, argv);
    Sniffer sniffer = Sniffer();

    parse.parseArguments();

    if (parse.doPrintInterfaces()) {
        sniffer.list_active_interfaces();
        return 0;
    }

    // bool udp = parse.getUdp();
    // bool tcp = parse.getTcp();

    string filter = parse.getFilter();
    sniffer.apply_filter(filter);

    sniffer.capture(parse.getPacketsCnt());
    

    // Sniffer sniffer = Sniffer("enp0s3");
    // sniffer.capture(10);
    return 0;
}