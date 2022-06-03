#define _CRT_SECURE_NO_WARNINGS
#include <string>
#include <iostream>
#include <pcap.h>
#include<time.h>
using namespace std;
void epoch(time_t rawtime, FILE* fp)
{
    struct tm  ts;
    char buf[80];
    ts = *localtime(&rawtime);
    strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
    for (int i = 15; i < 23;i++)
        fprintf(fp, "%c",buf[i]);
    printf("%s\n", buf);
}
int main(int argc, char *argv[])
{
    string file;
    printf("분석할 패킷 명을 입력하세요");
    cin>>file;
    //string file = "xxxxxx.pcap";
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);
    struct pcap_pkthdr *header;
    const u_char *data;
    u_int packetCount = 0; 
    FILE* fp;
    fp = fopen("aaaaa.pcap", "w");

    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        printf("Packet # %i\n", ++packetCount);
        printf("Packet size: %d bytes\n", header->len);
        if (header->len != header->caplen)
        printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
        fprintf(fp, "+---------+---------------+----------+\n");
        epoch(header->ts.tv_sec, fp);
        fprintf(fp, ",%.3d,%.3d   ETHER\n|0   ", header->ts.tv_usec/1000, header->ts.tv_usec%1000);
        for (u_int i=0; (i <= header->caplen ) ; i++)
            fprintf(fp,"|%.2x", data[i]);
        fprintf(fp,"\n\n");
    }
    fclose(fp);
}
