/*************************************************************************
  > File Name: 1.c
  > Author: zeng123456
  > Mail: zeng2010203921@163.com 
  > Created Time: 2016年06月15日 星期三 09时26分14秒
 ************************************************************************/

#include <pcap.h>
#include <stdio.h>

int main()
{

	char errBuf[PCAP_ERRBUF_SIZE], * device;

	device = pcap_lookupdev(errBuf);	//查看可用的网络设备

	if(device)
	{

		printf("success: device: %s\n", device);
	}
	else
	{

		printf("error: %s\n", errBuf);
	}

	return 0;
}
