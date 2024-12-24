#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <cmath>
#include <numeric>
#include <algorithm>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h> 
#include <arpa/inet.h>

using namespace std;

#define ETHERNET_HEADER_LEN 14

// ------------------------------Group By IP Port------------------------------
void GroupByIPPort(const char* filepath) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filepath, errbuf);
    if (handle == nullptr) {
        cerr << "Error opening file: " << errbuf << endl;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    unordered_map<string, int> ip_port_count;
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        const struct ip* ip_header = (struct ip*)(packet + ETHERNET_HEADER_LEN);
        auto ip_header_len = ip_header->ip_hl * 4;

        const struct udphdr* udp_header = (struct udphdr*)(packet + ETHERNET_HEADER_LEN + ip_header_len);

        string dst_ip = inet_ntoa(ip_header->ip_dst);
        uint16_t dst_port = ntohs(udp_header->uh_dport);
        auto dst_ip_port = dst_ip + "," + to_string(dst_port);

        ip_port_count[dst_ip_port]++;
    }
    pcap_close(handle);

    ofstream csv_file("group-by-ip-port.csv");
    if (!csv_file.is_open()) {
        cerr << "Error opening output file." << endl;
        return;
    }

    cout << "IP,Port,Count" << endl;
    csv_file << "IP,Port,Count" << endl;
    for (const auto& entry : ip_port_count) {
        cout << entry.first << "," << entry.second << endl;
        csv_file << entry.first << "," << entry.second << endl;
    }

    csv_file.close();
}
// ------------------------------Group By IP Port------------------------------

// --------------------------------- StatsGap ---------------------------------
void ExtractArrivalTimes(const char* filepath, vector<double>& arrival_times) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filepath, errbuf);
    if(!handle) {
        throw runtime_error(string("Error opening file: ") + errbuf);
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;
    while((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        arrival_times.push_back(header->ts.tv_sec + header->ts.tv_usec / 1e6);
    }

    if(res == -1) {
        auto err_msg = pcap_geterr(handle);
        pcap_close(handle);
        throw runtime_error(string("Error reading " + string(filepath) + ": ") + errbuf);
    }

    pcap_close(handle);
}

vector<pair<string, double>> ComputeStats(const vector<double>& intervals) {
    // compute
    vector<pair<string, double>> stats;
    double sum = 0.0, mean = 0.0, std_dev = 0.0, median = 0.0;
    auto size = intervals.size();

    sum = accumulate(intervals.begin(), intervals.end(), 0.0);
    mean = sum / size;
    
    double sum_squares = 0.0;
    for(const auto& val : intervals) {
        sum_squares += (val - mean) * (val - mean);
    }
    std_dev = sqrt(sum_squares / size);

    auto sorted_intervals = intervals;
    sort(sorted_intervals.begin(), sorted_intervals.end());
    median = sorted_intervals[size / 2];

    int pos1 = size * 1 / 100;
    int pos99 = size * 99 / 100;
    auto pr1 = (size * 1) % 100 == 0 ? 
        sorted_intervals[pos1] : (sorted_intervals[pos1] + sorted_intervals[pos1 + 1]) / 2;
    auto pr99 = (size * 99) % 100 == 0 ? 
        sorted_intervals[pos99] : (sorted_intervals[pos99] + sorted_intervals[pos99 + 1]) / 2;

    stats.push_back(make_pair("mean", mean));
    stats.push_back(make_pair("std", std_dev));
    stats.push_back(make_pair("median", median));
    stats.push_back(make_pair("1%", pr1));
    stats.push_back(make_pair("99%", pr99));

    return stats;
}

void StatsGap(const char* filepath1, const char* filepath2) {
    vector<double> arrival_times;
    try {
        ExtractArrivalTimes(filepath1, arrival_times);
        ExtractArrivalTimes(filepath2, arrival_times);
    }
    catch(const exception& ex) {
        throw;
    }

    sort(arrival_times.begin(), arrival_times.end());
    vector<double> intervals;
    for(int i = 1; i < arrival_times.size(); i++) {
        intervals.push_back(arrival_times[i] - arrival_times[i - 1]);
    }

    auto stats = ComputeStats(intervals);

    // output
    ofstream csv_file("gap_stats.csv");
    if (!csv_file.is_open()) {
        cerr << "Error opening output file gap_stats.csv." << endl;
        return;
    }

    cout << "stat,value" << endl;
    csv_file << "stat,value" << endl;
    for (const auto& stat : stats) {
        cout << stat.first << "," << stat.second << endl;
        csv_file << stat.first << "," << stat.second << endl;
    }

    csv_file.close();
}
// --------------------------------- StatsGap ---------------------------------

int main(int argc, char* argv[]) {
    if(argc < 3) {
        cerr << "Usage: ./main group-by-ip-port <filename>.pcap or ./main gap-stats <filename1>.pcap <filename2>.pcap" << endl;
        return 1;
    }

    auto cmd = string(argv[1]);
    if(cmd == "group-by-ip-port") {
        auto filepath = argv[2];
        try {
            GroupByIPPort(filepath);
        }
        catch(const exception& ex) {
            cerr << "An error occurred: " << ex.what() << endl;
            return EXIT_FAILURE;
        }
    }
    else if(cmd == "gap-stats") {
        auto filepath1 = argv[2];
        auto filepath2 = argv[3];
        try {
            StatsGap(filepath1, filepath2);
        }
        catch(const exception& ex) {
            cerr << "An error occurred: " << ex.what() << endl;
            return EXIT_FAILURE;
        }
    }
    else {
        cerr << "Usage: ./main group-by-ip-port <filename>.pcap or ./main gap-stats <filename1>.pcap <filename2>.pcap" << endl;
        return 1;
    }
    
    return 0;
}
