# Network-Packet-Analyzer
Analyze common network packets and display them. Java bit manipulation is utilized.

Reads a set of packets and produces a detailed summary of those packets. This program can run as a shell command. The syntax of the command is the following:
% java pktanalyzer datafile

The pktanalyzer program will extract and display the different headers of the captured packets in the file datafile. First, it displays the ethernet header fields of the captured frames. Second, if the ethernet frame contains an IP datagram, it prints the IP header. Third, it prints the packets encapsulated in the IP datagram. TCP, UDP, or ICMP packets can be encapsulated in the IP packet. 
