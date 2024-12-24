#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <unordered_map>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h> 
#include <arpa/inet.h>


#define ETHERNET_HEADER_LEN 14

void GroupByIPPort(const char* filepath) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filepath, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    std::unordered_map<std::string, int> ip_port_count;
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        const struct ip* ip_header = (struct ip*)(packet + ETHERNET_HEADER_LEN);
        auto ip_header_len = ip_header->ip_hl * 4;

        const struct udphdr* udp_header = (struct udphdr*)(packet + ETHERNET_HEADER_LEN + ip_header_len);

        std::string dst_ip = inet_ntoa(ip_header->ip_dst);
        uint16_t dst_port = ntohs(udp_header->uh_dport);
        auto dst_ip_port = dst_ip + "," + std::to_string(dst_port);

        ip_port_count[dst_ip_port]++;
    }
    pcap_close(handle);

    std::ofstream csv_file("group-by-ip-port.csv");
    if (!csv_file.is_open()) {
        std::cerr << "Error opening output file." << std::endl;
        return;
    }

    std::cout << "IP,Port,Count" << std::endl;
    csv_file << "IP,Port,Count" << std::endl;
    for (const auto& entry : ip_port_count) {
        std::cout << entry.first << "," << entry.second << std::endl;
        csv_file << entry.first << "," << entry.second << std::endl;
    }

    csv_file.close();
}

void StatsGap(const char* filepath1, const char* filepath2) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle1 = pcap_open_offline(filepath1, errbuf);
    if (handle1 == nullptr) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return;
    }
    pcap_t* handle2 = pcap_open_offline(filepath2, errbuf);
    if (handle2 == nullptr) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    std::vector<double> arrival_times;
    while(pcap_next_ex(handle1, &header, &packet) >= 0) {
        arrival_times.push_back(header->ts.tv_sec + header->ts.tv_usec / 1e6);
    }
    while(pcap_next_ex(handle2, &header, &packet) >= 0) {
        arrival_times.push_back(header->ts.tv_sec + header->ts.tv_usec / 1e6);
    }
    pcap_close(handle1);
    pcap_close(handle2);

    std::sort(arrival_times.begin(), arrival_times.end());

    std::vector<double> intervals;
    for(int i = 1; i < arrival_times.size(); i++) {
        intervals.push_back(arrival_times[i] - arrival_times[i - 1]);
    }

    // compute
    double sum = 0.0, mean = 0.0, std_dev = 0.0, median = 0.0;
    auto size = intervals.size();

    sum = std::accumulate(intervals.begin(), intervals.end(), 0);
    mean = sum / size;
    
    double sum_squares = 0.0;
    for(const auto& val : intervals) {
        sum_squares += (val - mean) * (val - mean);
    }
    std_dev = std::sqrt(sum_squares / size);

    auto sorted_intervals = intervals;
    std::sort(sorted_intervals.begin(), sorted_intervals.end());
    median = sorted_intervals[n / 2];

    auto p1 = sorted_intervals[n * 1 / 100];
    auto p99 = sorted_intervals[n * 99 / 100];

    // output
    std::ofstream csv_file("gap_stats.csv");
    if (!csv_file.is_open()) {
        std::cerr << "Error opening output file gap_stats.csv." << std::endl;
        return;
    }

    std::cout << "stat,value" << std::endl;
    csv_file << "stat,value" << std::endl;
    std::cout << "mean," << mean << std::endl;
    csv_file << "mean," << mean << std::endl;
    std::cout << "std," << std_dev << std::endl;
    csv_file << "std," << std_dev << std::endl;
    std::cout << "median," << median << std::endl;
    csv_file << "median," << median << std::endl;
    std::cout << "1%," << p1 << std::endl;
    csv_file << "1%," << p1 << std::endl;
    std::cout << "99%," << p99 << std::endl;
    csv_file << "99%," << p99 << std::endl;

    csv_file.close();
}


int main(int argc, char* argv[]) {
    if(argc < 3) {
        std::cerr << "Usage: ./main group-by-ip-port <filename>.pcap or ./main gap-stats <filename1>.pcap <filename2>.pcap" << std::endl;
        return 1;
    }

    auto cmd = std::string(argv[1]);
    if(cmd == "group-by-ip-port") {
        auto filepath = argv[2];
        GroupByIPPort(filepath);
    }
    else if(cmd == "gap-stats") {
        auto filepath1 = argv[2];
        auto filepath2 = argv[3];
        StatsGap(filepath1, filepath2);
    }
    else {
        std::cerr << "Usage: ./main group-by-ip-port <filename>.pcap or ./main gap-stats <filename1>.pcap <filename2>.pcap" << std::endl;
        return 1;
    }
    
    return 0;
}
