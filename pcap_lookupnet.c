/*************************************************************************
  > File Name: pcap_looknet.c
  > Author: zeng123456
  > Mail: zeng2010203921@163.com 
  > Created Time: 2016年06月15日 星期三 09时50分35秒
 ************************************************************************/

#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void show_ip_mask(char* dev)
{

	char errbuf[1024];
	struct in_addr addr;
	char *net,*mask;
	bpf_u_int32 netp,maskp;
	int err=pcap_lookupnet(dev,&netp,&maskp,errbuf);
					//返回可用网络设备的相关信息
					//dev:网络设备
					//netp:网络接口的ip地址
					//mask:网络接口的子网掩码
					//errbuf:错误信息
	if(err==-1){

		printf("couldn't detect the ip and maskp: %s\n",errbuf);
		return;
	}

	addr.s_addr=netp;
	net=inet_ntoa(addr);
	if(net==NULL){

		printf("ip error\n");
		return;
	}
	printf("ip: %s\n",net);
	addr.s_addr=maskp;
	mask=inet_ntoa(addr);
	if(mask==NULL){

		printf("mask errorn");
		return;
	}
	printf("mask: %s\n",mask);
}

int main()
{

	char *dev, errbuf[1024];
	char select='a';
	printf("select(dispaly the packet in detail)/n:( Y/N ?))");
	scanf("%c",&select);
	while(select!='Y'&&select!='y'&&select!='n'&&select!='N'){

		printf("input the error!\nplease input the Y/N/y/n:");
		scanf("%c",&select);
	}

	/*look for the net device*/
	dev=pcap_lookupdev(errbuf);		//查看可用网络设备
	if(dev==NULL){

		printf("couldn't find default device: %s\n",errbuf);
		return 1;
	}
	else{

		printf("fidn success: device :%s\n",dev);
	}

	/*ip mask display*/
	show_ip_mask(dev);
	return 0;
}
