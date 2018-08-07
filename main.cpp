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


void usage();
void convrt_mac(const char *, char *, int);
int getMacAddress(char *);

int main(int argc, char* argv[]) {
	char test [15]={0,};
	if (argc != 2) {
		usage(); return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	getMacAddress(test);
	printf("%s\n",test);


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

void usage() {
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int getMacAddress(char *mac)
{

	int sock;
	struct ifreq ifr;
	char mac_adr[18] = {0,};
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
	//convert format ex) 00:00:00:00:00:00
	//	convrt_mac( ether_ntoa((struct ether_addr *)(ifr.ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr) -1 );
	strcpy(mac, ether_ntoa((struct ether_addr *)ifr.ifr_hwaddr.sa_data));
	close(sock);
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

