#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <pcap.h>



#pragma pack (1)

#define DEBUG_LEVEL_ 3

#ifdef  DEBUG_LEVEL_
#define dp(n, fmt, args...)	if (DEBUG_LEVEL_ <= n) fprintf(stderr, "%s:%d,"fmt, __FILE__, __LINE__, ## args)
#define dp0(n, fmt)		if (DEBUG_LEVEL_ <= n) fprintf(stderr, "%s:%d,"fmt, __FILE__, __LINE__)
#define _dp(n, fmt, args...)	if (DEBUG_LEVEL_ <= n) fprintf(stderr, " "fmt, ## args)
#else	/* DEBUG_LEVEL_ */
#define dp(n, fmt, args...)
#define dp0(n, fmt)
#define _dp(n, fmt, args...)
#endif	/* DEBUG_LEVEL_ */

#define IP_ALEN 4

typedef struct _arp_address{
	uint8_t sha[ETH_ALEN];
	uint8_t sip[IP_ALEN];
	uint8_t tha[ETH_ALEN];
	uint8_t tip[IP_ALEN];
}arp_address;

void usage();
void convrt_mac(const char *, char *, int);
int getMacAddress(uint8_t *);
void send_arp(pcap_t *, arp_address, bool); 
void delete_dot(char *, uint8_t *);


int main(int argc, char* argv[]) {
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	arp_address address;

	if (argc != 4) {
		usage(); return -1;
	}

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	getMacAddress(address.sha);

	delete_dot(argv[2],address.sip);
	for(int i = 0; i < 4; i++){
		printf("%2d:", address.sip[i]);
	}
	/*while (true) {
	  struct pcap_pkthdr* header;
	  const u_char* packet;
	  int res = pcap_next_ex(handle, &header, &packet);
	  if (res == 0) continue;
	  else if (res == -1 || res == -2) break;
	  }
	 */

	pcap_close(handle);
	return 0;
}

void send_arp(pcap_t * handle,arp_address *address, bool attack){
	struct ether_header ether;
	struct arphdr arp;
	uint8_t *packet;
	uint32_t size;
	
	size = sizeof(ether) + sizeof(arp) + sizeof(address);
	packet = (uint8_t *)malloc(size);

	memcpy(ether.ether_dhost,address->tha,ETH_ALEN);
	memcpy(ether.ether_shost,address->sha,ETH_ALEN);
	ether.ether_type = ETHERTYPE_ARP;

	arp.ar_hrd = ARPHRD_ETHER; 
	arp.ar_pro = ETHERTYPE_IP; 
	arp.ar_hln = ETH_ALEN;
	arp.ar_pln = IP_ALEN;
	arp.ar_op = ARPOP_REQUEST; 

	if (attack){
		memset(address->tha,0x0,ETH_ALEN);
		memset(ether.ether_dhost,0xff,ETH_ALEN);
		arp.ar_op = ARPOP_REPLY;
	}
	
	memcpy(packet,&ether,sizeof(ether));
	memcpy(packet+sizeof(ether),&arp,sizeof(arp));
	memcpy(packet+size-sizeof(address),address,sizeof(address));
	pcap_sendpacket(handle,packet,size);
}

void delete_dot(char *src, uint8_t *des){
	char *token;
	token = strtok(src,".");
	do{
		*des = static_cast<uint8_t>(atoi(token));	
		des++;
	}while(token = strtok(NULL,"."));
	return;
}

void usage() {
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int getMacAddress(uint8_t *mac)
{
	int sock;
	struct ifreq ifr;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) 
	{
		dp(4, "socket");
		return 0;
	}
	strcpy(ifr.ifr_name, "ens33");
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0)    
	{
		dp(4, "ioctl() - get mac");
		close(sock);
		return 0;
	}
	for(int i = 0; i < 6; i++){
		mac[i] = (uint8_t)ifr.ifr_hwaddr.sa_data[i];
	}
	return 1;
}

void convrt_mac(const char *data, char *cvrt_str, int sz)
{
	char buf[128] = {0,};
	char t_buf[8];
	char *stp = strtok( (char *)data , ":" );
	int temp=0;
	do
	{
		memset( t_buf, 0, sizeof(t_buf) );
		sscanf( stp, "%x", &temp );
		snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
		strncat( buf, t_buf, sizeof(buf)-1 );
		strncat( buf, ":", sizeof(buf)-1 );
	} while( (stp = strtok( NULL , ":" )) != NULL );

	buf[strlen(buf) -1] = '\0';
	strncpy( cvrt_str, buf, sz );
}

