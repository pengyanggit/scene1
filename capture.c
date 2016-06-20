/*************************************************************************
  > File Name: capture.c
  > Author: zeng123456
  > Mail: zeng2010203921@163.com 
  > Created Time: 2016年06月15日 星期三 10时06分59秒
 ************************************************************************/

#include
#include
#define max 1024
#define number 5
typedef struct ip_address{

	    u_char byte1;
	    u_char byte2;
	    u_char byte3;
	    u_char byte4;
}ip_address;
typedef struct mac_address{

	    u_char byte1;
	    u_char byte2;
	    u_char byte3;
	    u_char byte4;
	    u_char byte5;
	    u_char byte6;
}mac_address;

/*pcap_pkthdr包含三个参数：ts时间戳，caplen已捕获部分到长度，len该包到脱机长度*/
int call(u_char *argument,const struct pcap_pkthdr* pack,const u_char *content)						/*数据包回掉函数*/
{
	     
		       int ipaddlen=4,macaddlen=6,iplen=20,tcplen=20,udplen=8;  
		    const u_char *mac;
	    const u_char *p;
	    const u_char *smac;
	    const u_char *dmac;
	    const u_char *sipadd;
	    const u_char *dipadd;
	    const u_char *llc;
	    const u_char *ip;
	        const u_char *tcp;
	        const u_char *udp;
	        int nice = 0;	/*默认不含有应用层数据*/
	    mac= &content[18];	/*除掉18字节的包参数信息*/
	    dmac = &mac[4];
	    smac = &mac[10];
	    llc = &mac[24];
	        ip = &llc[8];
	        iplen = (int)(ip[0]&0x0F);/*获取首部长度*/
	        if(ip[9]==0x06)/*确定含有tcp*/
		       {

			           tcp = &ip[iplen];
			           tcplen = (int)(((tcp[12]&0xF0)>>4)*4);/*获取tcp报文首部长度*/
			           if(pack->len >(18+24+8+iplen+tcplen+4))/*确定包含应用层数据*/
				             nice = 1;
			       }
	        if(ip[9]==0x11)/*确定含有udp报文*/
		       {

			                if(pack->len >(18+24+8+iplen+8+4))/*确定包含应用层数据*/
				                 nice = 1;
			            }

	        if(nice == 1)
		           {

			                   sipadd = &ip[12];
			           dipadd = &ip[16];

			                   for (macaddlen;macaddlen>0;macaddlen--)
				           {

					               printf("x",smac[6-macaddlen]);
					               printf(":");
					           }
			           for (ipaddlen;ipaddlen>0;ipaddlen--)
				           {

					               printf("%d",sipadd[4-ipaddlen]);
					               printf(":");
					           }
			                  
				           macaddlen=6;
			           ipaddlen=4;
			           printf("\n");
			           for (macaddlen;macaddlen>0;macaddlen--)
				           {

					               printf("x",dmac[6-macaddlen]);
					               printf(":");
					           }
			           for (ipaddlen;ipaddlen>0;ipaddlen--)
				           {

					               printf("%d",dipadd[4-ipaddlen]);
					               printf(":");
					           }
			                  
				           printf("\n");
			           }
	        return 0;
}
int main(int argc,char *argv[])
{

	        ip_address ip[number];
	        mac_address mac[number];
	    pcap_t *handle;/*会话句柄*/
	    char error[100];/*存储错误信息字符串*/
	    struct pcap_pkthdr pack; /*包参数，包括ts时间戳，caplen已捕获部分到长度，len该包到脱机长度*/
	    const u_char *content;/*实际的包*/
	        struct bpf_program filter;/*已经编译好的过滤器*/
	        char filter_app[] = "tcp or udp";/*构造过滤表达式*/
	    char file[]="test.pcap";
	    if((handle=pcap_open_offline(file,error))==NULL)  /*打开文件*/
		    {

			        printf("%s\n",error);
			        return 0;
			    }

	      pcap_compile(handle,&filter,filter_app,1,0);/*函数返回-1为失败*/

	        if(pcap_setfilter(handle,&filter)==0)/*成功返回0.不成功返回-1*/

		       pcap_loop(handle,-1,call,NULL);  /*捕获数据包*/
		    return 1;
}
