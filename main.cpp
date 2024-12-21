#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unordered_map>
#include <arpa/inet.h>

using namespace std;

// 統計數據結構：以目標IP和端口為鍵，封包數量為值
unordered_map<string, int> packet_counts;

// 用來解析TCP/UDP封包的函數
void process_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    // 解析IP頭部
    struct ip* ip_header = (struct ip*)(packet + 14); // 跳過以太網標頭
    string dest_ip = inet_ntoa(ip_header->ip_dst);

    // 解析傳輸層協議 (TCP/UDP)
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2));
        uint16_t dest_port = ntohs(tcp_header->th_dport);
        string key = dest_ip + ":" + to_string(dest_port);
        packet_counts[key]++;
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl << 2));
        uint16_t dest_port = ntohs(udp_header->uh_dport);
        string key = dest_ip + ":" + to_string(dest_port);
        packet_counts[key]++;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <PCAP file>" << endl;
        return 1;
    }

    // 打開PCAP文件
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (handle == nullptr) {
        cerr << "Error opening file: " << errbuf << endl;
        return 1;
    }

    // 讀取PCAP文件中的每一個封包
    struct pcap_pkthdr header;
    const u_char* packet;
    while ((packet = pcap_next(handle, &header)) != nullptr) {
        process_packet(&header, packet);
    }

    // 顯示統計結果
    cout << "Packet counts by destination IP and port:" << endl;
    for (const auto& entry : packet_counts) {
        cout << entry.first << ": " << entry.second << " packets" << endl;
    }

    // 關閉PCAP文件
    pcap_close(handle);
    return 0;
}
