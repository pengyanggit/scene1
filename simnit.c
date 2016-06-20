/*************************************************************************
  > File Name: simnit.c
  > Author: zeng123456
  > Mail: zeng2010203921@163.com 
  > Created Time: 2016年06月15日 星期三 10时16分21秒
 ************************************************************************/

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#define MAXBYTES2CAPTURE 2048
void processPacket(u_char *arg,const struct pcap_pkthdr *pkthdr,const u_char *packet)
{
	int i=0;
	int *counter=(int *)arg;
	printf("packet Count:%d\n",++(*counter));
	printf("Receoved Packet size :%d\n",pkthdr->len);
	printf("Payload\n");
	for(i=0;i<pkthdr->len;i++)
	{
		if(isprint(packet[i]))
			printf("%c ",packet[i]);
		else
			printf(". ");
		if((i%16==0 && i!=0)||i==(pkthdr->len -1))
			printf("\n");
	}
	return;
}
int main()
{
	int count=0;
	pcap_t *descr=NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device=NULL;
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	device=pcap_lookupdev(errbuf);
	printf("Opening device %s\n",device);
	descr=pcap_open_live(device,MAXBYTES2CAPTURE,1,512,errbuf);
	pcap_loop(descr,-1,processPacket,(u_char *)&count);
	return 0;
}
