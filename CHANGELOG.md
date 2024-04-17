## Implemented features

The project can do bare minimum required by the assignment. Also, it can print out some additional info such as used filters

## Possible issues

There wasnt tested edge cases such as too big number of packets specified with `-n`. Also, maybe too much information is printed in packet content, comparing to `tcpdump`. Possible packet loss on high load, however it mostly depends on `libpcap` capability.