/*************************************************************************
  > File Name: loop.c
  > Author: zeng123456
  > Mail: zeng2010203921@163.com 
  > Created Time: 2016年06月14日 星期二 17时56分43秒
 ************************************************************************/

//the second update
/*This is loop.c ,update*/

#include"trace.h"
int gotalarm;
const char *icmpcode_v4(int code){

	static char errbuf[100];
	switch(code){

		case 0:return("network unreachable");   
		case 1:return("host unreachable");
		case 2:return("protocol unreachable");
		case 3:return("port unreachable");  
		case 4:return("fragmentation required but DF bit set"); 
		case 5:return("source route failed");   
		case 6:return("destination network unknown");   
		case 7:return("destination host unknown");  
		case 8:return("source host isolated(obsolete)");    
		case 9:return("destination network administartively prohibited");
		case 10:return("destination host administartively prohibited"); 
		case 11:return("network unreachable for TOS");  
		case 12:return("host unreachable for TOS"); 
		case 13:return("communication error");  
		case 14:return("host recedenc violation");  
		case 15:return("precedence cutoff in effect");  
		default:sprintf(errbuf,"unknown code %d",code);
	}   
	return errbuf;  
}
void sig_alrm(int signo){

	gotalarm=1;
	return;
}
void tv_sub(struct timeval *out,struct timeval *in){

	if((out->tv_usec-=in->tv_usec)<0){

		--out->tv_sec;
		out->tv_sec+=1000000;
	}   
	out->tv_sec-=in->tv_sec;
}
void traceloop(void){

	int seq,code,done;
	double rtt;
	struct rec *rec;
	struct timeval tvrecv;
	if((recvfd=socket(pr->sasend->sa_family,SOCK_RAW,pr->icmpproto))<0){

		printf("recvfd:socket failed\n");
		return;
	}
	setuid(getuid());
	if((sendfd=socket(pr->sasend->sa_family,SOCK_DGRAM,0))<0){

		printf("sendfd:socket failed\n");
		return;
	}

	pr->sabind->sa_family=pr->sasend->sa_family;
	sport=(getpid()&0xffff) | 0x8000;
	((struct sockaddr_in*)pr->sabind)->sin_port=htons(sport);

	if(bind(sendfd,pr->sabind,pr->salen)<0){

		printf("bind error\n");
		return;
	}

	sig_alrm(SIGALRM);
	seq=0;
	done=0;
	for(ttl=1;ttl<=max_ttl&&done==0;ttl++){

		setsockopt(sendfd,pr->ttllevel,pr->ttloptname,&ttl,sizeof(int));        bzero(pr->salast,pr->salen);
		printf("%2d ",ttl);
		fflush(stdout);
		for(probe=0;probe<nprobes;probe++){


			rec=(struct rec*)sendbuf;
			rec->rec_seq=++seq;
			rec->rec_ttl=ttl;

			gettimeofday(&rec->rec_tv,NULL);
			((struct sockaddr_in*)pr->sasend)->sin_port=htons(dport+seq);
			if(sendto(sendfd,sendbuf,datalen,0,pr->sasend,pr->salen)<0){

				perror("bad sendto");
				continue;
			}

			if((code=(*pr->recv)(seq,&tvrecv))==-3){

				printf(" *");
			}else{

				char str[NI_MAXHOST];
				if(memcmp(pr->sarecv,pr->salast,pr->salen)!=0){

					if(getnameinfo(pr->sarecv,pr->salen,str,sizeof(str),NULL,0,0)==0){

						printf(" %s (%s)",str,inet_ntoa(((struct sockaddr_in*)pr->sarecv)->sin_addr));
					}else{

						printf(" %s",inet_ntoa(((struct sockaddr_in*)pr->sarecv)->sin_addr));
					}
					memcpy(pr->salast,pr->sarecv,pr->salen);
				}
				tv_sub(&tvrecv,&rec->rec_tv);
				rtt=tvrecv.tv_sec*1000.0+tvrecv.tv_usec/1000;
				printf("  %.3f ms",rtt);

				if(code==-1){

					done++;
				}else if(code>0){

					printf(" (ICMP %s)",(*pr->icmpcode)(code));
				}
			}
			fflush(stdout);
		}
		printf("\n");
	}
}
int recv_v4(int seq,struct timeval *tv){

	int hlen1,hlen2,icmplen,ret;
	socklen_t len;
	ssize_t n;
	struct ip *ip,*hip;
	struct icmp *icmp;
	struct udphdr *udp;

	gotalarm=0;
	for(;;){

		if(gotalarm){

			return -3;
		}
		len=pr->salen;
		alarm(3);
		n=recvfrom(recvfd,recvbuf,sizeof(recvbuf),0,pr->sarecv,&len);
		if(n<0){

			if(errno==EINTR){

				continue;
			}else{

				printf("recvfrom error\n");
				return 0;
			}
		}else{

			alarm(0);
		}


		ip=(struct ip*)recvbuf;
		hlen1=ip->ip_hl<<2;
		icmp=(struct icmp*)(recvbuf+hlen1);
		if((icmplen=n-hlen1)<8){

			continue;
		}
		if(icmp->icmp_type==ICMP_TIMXCEED&&
				icmp->icmp_code==ICMP_TIMXCEED_INTRANS){

			if(icmplen<8+sizeof(struct ip)){

				continue;
			}
			hip=(struct ip*)(recvbuf+hlen1+8);
			hlen2=hip->ip_hl<<2;
			if(icmplen<8+hlen2+4){

				continue;
			}
			udp=(struct udphdr *)(recvbuf+hlen1+8+hlen2);
			if(hip->ip_p==IPPROTO_UDP&&
					udp->source==htons(sport)&&
					udp->dest==htons(dport+seq)){

				ret=-2;
				break;
			}
		}else if(icmp->icmp_type==ICMP_UNREACH){

			if(icmplen<8+sizeof(struct ip))
				continue;
			hip=(struct ip*)(recvbuf+hlen1+8);
			hlen2=hip->ip_hl<<2;
			if(icmplen<8+hlen2+4)
				continue;
			udp=(struct udphdr*)(recvbuf+hlen1+8+hlen2);
			if(hip->ip_p==IPPROTO_UDP&&
					udp->source==htons(sport)&&
					udp->dest==htons(dport+seq)){

				if(icmp->icmp_code==ICMP_UNREACH_PORT)
					ret=-1;     
				else
					ret=icmp->icmp_code;
				break;
			}
		}
	}
	gettimeofday(tv,NULL);
	return ret;
}
