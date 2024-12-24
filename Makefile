build:
	g++ -o main main.cpp -lpcap
clean:
	rm -rf main *.csv
group:
	./main group-by-ip-port data.pcap
stat:
	./main gap-stats data.pcap data2.pcap

.PHONY:
	build clean group stat