#include "Sniffer.hpp"
#include "ParseArgs.hpp"

using namespace std;

int main(int argc, char** argv) {
    Parse parse = Parse(argc, argv);

    parse.parseArguments();

    if (parse.doPrintInterfaces()) {
        Sniffer sniffer = Sniffer();
        sniffer.list_active_interfaces();
        return 0;
    }

    // bool udp = parse.getUdp();
    // bool tcp = parse.getTcp();
    Sniffer sniffer = Sniffer(parse.getInterface());

    string filter = parse.getFilter();
    sniffer.applyFilter(filter);

    sniffer.capture(parse.getPacketsCnt());
    

    // Sniffer sniffer = Sniffer("enp0s3");
    // sniffer.capture(10);
    return 0;
}