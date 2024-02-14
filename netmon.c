/*
 *  netmon - Packet sniffer using libpcap library
 *  Copyright (C) 2024  Resilience Theatre
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * 
 *  Based on several examples:
 * 
 *  https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 *  http://codeblurbs.blogspot.com/2016/07/a-simple-libpcap-example-for-live.html
 *  http://yuba.stanford.edu/~casado/pcap/section3.html
 * 
 */
 
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <pthread.h>
#include "log.h"
#include "ini.h"

void display_udp_packet(const u_char *Buffer , int Size);
void display_ip_header(const u_char * Buffer, int Size);
void display_ethernet_header(const u_char *Buffer, int Size);

struct sockaddr_in source,dest;
int i,j;	
pthread_t timeout_thread_id;
int rxactive=0;
int rxstate=0;
char *rx_start_command = NULL;
char *rx_end_command = NULL;
char *trigger_port = NULL;
int trigger_port_value;


pcap_t * pcapinterface( const char * interface_name, const char* capturefilter )
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int success = 0;
	// Create a packet capture handle for the specified interface
	pcap_t * pcap = pcap_create( interface_name, errbuf );
	if( pcap == NULL )
	{
        log_error("[%d] Unable to create pcap for interface %s (%s).", getpid(), interface_name, errbuf);        
		goto exit;
	}
	// Deliver packets as soon as they arrive. See the pcap man page for more info.
	if( pcap_set_timeout( pcap, 1 ) != 0 )
	{
        log_error("[%d] Unable to configure timeout.", getpid() );        
		goto exit;
	}
	// When immediate mode is enabled, reads return immediately upon packet reception.
	// Otherwise, a read will block until either the kernel buffer becomes full or a timeout occurs.
	if( pcap_set_immediate_mode( pcap, 1 ) != 0 )
	{
        log_error("[%d]Unable to configure immediate mode.", getpid() );        
		goto exit;
	}
	// Activate packet capture handle to look at packets on the network
	int activateStatus = pcap_activate( pcap );
	if( activateStatus < 0 )
	{
        log_error("[%d] Activate failed", getpid() );        
		goto exit;
	}
	// Set ethernet link-layer header type
	if( pcap_set_datalink( pcap, DLT_EN10MB ) )
	{
        log_error("[%d] Set datalink failed", getpid() );        
		goto exit;
	}
	
    // Set capture filter
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 netp;           /* ip                        */
    bpf_u_int32 maskp;          /* subnet mask               */
    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(interface_name,&netp,&maskp,errbuf);
    
    /* Lets try and compile the program.. non-optimized */
    // "port 6000 and dst 192.168.5.20"
    if(pcap_compile(pcap,&fp,capturefilter,0,netp) == -1)
    { 
        log_error("[%d] Error calling pcap_compile", getpid() ); 
        exit(1); 
    }
    /* set the compiled program as the filter */
    if(pcap_setfilter(pcap,&fp) == -1)
    { 
        log_error("[%d] Error setting filter", getpid() );
        exit(1); 
    }
	success = 1;
	
exit:
	
	if( success == 0 )
	{
		if( pcap )
		{
			pcap_close( pcap );
			pcap = NULL;
		}
	}
	return pcap;
}

void pcapmonitor( pcap_t * pcap )
{
	int pcapFD = pcap_get_selectable_fd( pcap );
	if( pcapFD < 0 )
		return;
	
	fd_set allFileDescriptorSet;
	
	FD_ZERO( &allFileDescriptorSet );
	FD_SET( pcapFD, &allFileDescriptorSet );
	
	for( ;; )
	{
		fd_set readFileDescriptorSet = allFileDescriptorSet;
		
		int readyCount = select( pcapFD + 1, &readFileDescriptorSet, NULL, NULL, NULL );
		if( readyCount < 0 )
			break;
		
		if( FD_ISSET( pcapFD, &readFileDescriptorSet ) )
		{
			struct pcap_pkthdr * pcapHeader;
			const u_char * packetPtr;
			int packetCount = pcap_next_ex( pcap, &pcapHeader, &packetPtr );
			
			if( packetCount < 0 )
				break;
			
            if( pcapHeader->caplen >= sizeof( struct ether_header ) )
			{
				struct ether_header * eh = (struct ether_header *)packetPtr;   
                struct iphdr *iph = (struct iphdr*)(packetPtr + sizeof(struct ethhdr));
                switch (iph->protocol) //Check the Protocol and do accordingly...
                {
                    case 17: 
                        display_udp_packet(packetPtr , pcapHeader->len);
                        break;
                    default: 
                        break;
                }
			}
		}
	}
}

void *timeout_thread(void *arguments)
{
    
    while (1) 
    {
        
        if ( rxactive > 0 && rxstate == 1)
        {
            rxactive--;
        }
        if ( rxactive == 0 && rxstate == 1)
        {
            log_info("[%d] End of RX ", getpid() );
            system(rx_end_command);
            rxactive=0;
            rxstate=0;
        }
        sleep(1);
        
    }
}


int main(int argc, char *argv[])
{
    int c;
    char *ini_file = NULL;
    char *netdev = NULL;
    char *capturefilter = NULL;
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];
    
    while ((c = getopt (argc, argv, "i:h")) != -1)
	switch (c)
	{
    case 'i':
        ini_file = optarg;
        break;
    case 'h':
		fprintf(stderr,"netmon \n");
        fprintf(stderr,"Usage: -i [ini file]\n");
		return 1;
	break;
		default:
		break;
	}
    log_set_level(LOG_INFO);
    // log_set_quiet(TRUE);
    
    /* Timeout thread */
    pthread_create(&timeout_thread_id, NULL, &timeout_thread, NULL);
    
    /* Read ini-file */
    ini_t *config = ini_load(ini_file);
    /* Read ini-file */
    ini_sget(config, "netmon", "network_device", NULL, &netdev);
    ini_sget(config, "netmon", "capturefilter", NULL, &capturefilter); 
    ini_sget(config, "netmon", "rx_start_command", NULL, &rx_start_command);
    ini_sget(config, "netmon", "rx_end_command", NULL, &rx_end_command);
    ini_sget(config, "netmon", "trigger_port", NULL, &trigger_port);
    trigger_port_value = atoi(trigger_port);
    /* Open network device */
    log_info("[%d] Capture filter: %s", getpid(),capturefilter);
    log_info("[%d] Trigger port: %d", getpid(),trigger_port_value );
    log_info("[%d] Opening device: %s", getpid(), netdev);
    /* Immediate method */
    pcap_t * pcap = pcapinterface( netdev, capturefilter );
    pcapmonitor( pcap );
    pthread_join(timeout_thread_id, NULL);
	return 0;	
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	switch (iph->protocol) 
	{
		case 17: 
            display_udp_packet(buffer , size);
			break;
		
		default: // ARP etc.
			break;
	}
}


void display_udp_packet(const u_char *Buffer , int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
    log_debug("[%d] UDP packet",getpid() );
    
	display_ip_header(Buffer,Size);			
	
	log_debug("[%d]   UDP Header",getpid());
	log_debug("[%d]    Source Port      : %d",getpid() , ntohs(udph->source));
	log_debug("[%d]    Destination Port : %d",getpid() , ntohs(udph->dest));
	log_debug("[%d]    UDP Length       : %d",getpid() , ntohs(udph->len));
	log_debug("[%d]    UDP Checksum     : %d",getpid() , ntohs(udph->check));
    
    // ntohs(udph->dest) == trigger_port_value &&
    if (rxstate == 0)
    {
        log_info("[%d] Start of RX ", getpid() );
        system(rx_start_command);
        rxactive=2;
        rxstate=1;
    }
    //  ntohs(udph->dest) == trigger_port_value && 
    if (rxstate == 1)
    {
        rxactive=2;
        rxstate=1;
    }
}

void display_ip_header(const u_char * Buffer, int Size)
{
	display_ethernet_header(Buffer , Size);
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	log_debug("[%d]   IP Header",getpid() );
	log_debug("[%d]    IP Version        : %d",getpid(),(unsigned int)iph->version);
	log_debug("[%d]    IP Header Length  : %d DWORDS or %d Bytes",getpid(),(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	log_debug("[%d]    Type Of Service   : %d",getpid(),(unsigned int)iph->tos);
	log_debug("[%d]    IP Total Length   : %d  Bytes(Size of Packet)",getpid(),ntohs(iph->tot_len));
	log_debug("[%d]    Identification    : %d",getpid(),ntohs(iph->id));
	// log_debug("[%d] Reserved ZERO Field   : %d",getpid(),(unsigned int)iphdr->ip_reserved_zero);
	// log_debug("[%d] Dont Fragment Field   : %d",getpid(),(unsigned int)iphdr->ip_dont_fragment);
	// log_debug("[%d] More Fragment Field   : %d",getpid(),(unsigned int)iphdr->ip_more_fragment);
	log_debug("[%d]    TTL      : %d",getpid(),(unsigned int)iph->ttl);
	log_debug("[%d]    Protocol : %d",getpid(),(unsigned int)iph->protocol);
	log_debug("[%d]    Checksum : %d",getpid(),ntohs(iph->check));
	log_debug("[%d]    Source IP        : %s",getpid() , inet_ntoa(source.sin_addr) );
	log_debug("[%d]    Destination IP   : %s",getpid() , inet_ntoa(dest.sin_addr) );
       
}

void display_ethernet_header(const u_char *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
    log_debug("[%d]  Ethernet Header:", getpid()  );
    log_debug("[%d]   Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X", getpid(), eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]  );
    log_debug("[%d]   Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X", getpid(), eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]  );
    log_debug("[%d]   Protocol            : %u", getpid(),(unsigned short)eth->h_proto  );
}


