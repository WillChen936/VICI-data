#include <iostream>
#include <unordered_map>
#include <netinet/ip.h> // IP header
#include <netinet/udp.h> // UDP header
#include <arpa/inet.h> // inet_ntoa
#include <pcap.h>

using namespace std;

int main(int argc, char* argv[]) {
    const char* filepath = "./data.pcap";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filepath, errbuf);
    if (handle == nullptr) {
        cerr << "Error opening file: " << errbuf << endl;
        return 1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    std::unordered_map<std::string, int> ip_count_map;
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        std::cout << "Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec;
        std::cout << " | Captured Length: " << header->caplen << " bytes";
        std::cout << " | Original Length: " << header->len << " bytes" << std::endl;
        std::cout << std::endl;

        struct ip* ip_header = (struct ip *)(packet + 14);
        std::cout << std::hex << "packet + 13: 0x" << +*(packet + 13) << " | "
              << "packet + 14: 0x" << +*(packet + 14) << " | "
              << "packet + 15: 0x" << +*(packet + 15) << std::endl;
        std::cout << "IP Header:" << std::endl;
        std::cout << "  Version: " << (int)ip_header->ip_v << std::endl;
        std::cout << "  Header Length: " << (int)ip_header->ip_hl * 4 << " bytes" << std::endl; // ip_hl 是 4 位，表示頭部長度（單位：4 字節）
        std::cout << "  Type of Service: " << (int)ip_header->ip_tos << std::endl;
        std::cout << "  Total Length: " << ntohs(ip_header->ip_len) << " bytes" << std::endl; // ntohs 轉換為主機字節序
        std::cout << "  Identification: " << ntohs(ip_header->ip_id) << std::endl;
        std::cout << "  Fragment Offset: " << ntohs(ip_header->ip_off) << std::endl;
        std::cout << "  Time to Live: " << (int)ip_header->ip_ttl << std::endl;
        std::cout << "  Protocol: " << (int)ip_header->ip_p << std::endl;
        std::cout << "  Header Checksum: " << ntohs(ip_header->ip_sum) << std::endl;

        // 輸出源地址和目的地址
        struct in_addr src_addr = ip_header->ip_src;
        struct in_addr dst_addr = ip_header->ip_dst;
        std::cout << "  Source IP: " << inet_ntoa(src_addr) << std::endl;
        std::cout << "  Destination IP: " << inet_ntoa(dst_addr) << std::endl;
        std::cout << "------------------------------" << std::endl;

        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        ip_count_map[dest_ip]++;
    }

    for (const auto &entry : ip_count_map) {
        std::cout << "Destination IP: " << entry.first << " -> Packet Count: " << entry.second << std::endl;
    }

    pcap_close(handle);
    return 0;
}
