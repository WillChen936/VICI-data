#include <iostream>
#include <pcap.h>

using namespace std;

int main(int argc, char* argv[]) {
    char* filepath = "./data.pcap"
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filepath, errbuf);
    if (handle == nullptr) {
        cerr << "Error opening file: " << errbuf << endl;
        return 1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        std::cout << "Packet Length: " << header->len << " bytes" << std::endl;
        std::cout << packet << std::endl;
    }

    pcap_close(handle);
    return 0;
}
