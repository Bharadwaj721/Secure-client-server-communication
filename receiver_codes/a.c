#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<sys/stat.h>
#include<fcntl.h>
#include <sys/wait.h>
#include<poll.h>
#include<sys/msg.h>
#include<sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

char buf[1000];
void send_msg()
{
    int sfd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in add;
    add.sin_family = AF_INET;
    add.sin_port= htons(9503);  
    add.sin_addr.s_addr =inet_addr("10.42.0.126");
    int reuse=1;
    setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    int c= connect(sfd,(struct sockaddr*)&add,sizeof(add));
    send(sfd,buf,sizeof(buf),0);
    printf("sent successfully");
    close(sfd);
    return;
}
#define SNAP_LEN 1518       /* default snap length (maximum bytes per packet to capture) */
#define SIZE_ETHERNET 14    /* ethernet headers are always exactly 14 bytes [1] */
#define ETHER_ADDR_LEN	6   /* Ethernet addresses are 6 bytes */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* don't fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
struct sniff_ethernet       /* Ethernet header */
{
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};
struct sniff_ip 	    /* IP header */
{
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
typedef u_int tcp_seq;  /* TCP header */
struct sniff_tcp 
{
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        u_char  th_flags;
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	int i,gap;                                    //print data in rows of 16 bytes: offset   hex   ascii
	const u_char *ch;                         //00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
	printf("%05d   ", offset);                 /* offset */
	ch = payload;				   /* hex */
	for(i = 0; i < len; i++) 
	{
		printf("%02x ", *ch);             /* print extra space after 8th byte for visual aid */
		ch++;
		if (i == 7) printf(" ");
	}
	if (len < 8) printf(" ");                               ///* print space to handle line less than 8 bytes */
	if (len < 16) 					///* fill hex gap with spaces if not full line */
	{
		gap = 16 - len;
		for (i = 0; i < gap; i++) printf("   ");
	}
	printf("   ");
	ch = payload;
	for(i = 0; i < len; i++) 		/* ascii (if printable) */
	{
		if (isprint(*ch)) printf("%c", *ch);
		else printf(".");
		ch++;
	}
	printf("\n");
}
void print_payload(const u_char *payload, int len)    //print packet payload data (avoid printing binary data)
{
        int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;
	if (len <= 0) return;
	if (len <= line_width)      /* data fits on one line */
	{
		print_hex_ascii_line(ch, len, offset);
		return;
	}
	for ( ;; )   /* data spans multiple lines */
	{
		line_len = line_width % len_rem;   /* compute current line length */
		print_hex_ascii_line(ch, line_len, offset);   /* print line */
		len_rem = len_rem - line_len;     /* compute total remaining */
		ch = ch + line_len;                /* shift pointer to remaining bytes to print */
		offset = offset + line_width;      /* add offset */
		if (len_rem <= line_width) 	  /* check if we have line width chars or less */
		{
			print_hex_ascii_line(ch, len_rem, offset);   /* print last line and get out */
			break;
		}
	}
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)    //dissect/print packet
{

	static int count = 1;                   /* packet counter */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	int size_ip;
	int size_tcp;
	int size_payload;
	printf("\nPacket number %d:\n", count);
	count++;
	ethernet = (struct sniff_ethernet*)(packet);/* define ethernet header */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);  /* define/compute ip header offset */
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) 
	{
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	printf("       From: %s\n", inet_ntoa(ip->ip_src));    /* print source and destination IP addresses */
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	printf("       Protocol = %d\n",ip->ip_p);   /* determine protocol */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) 
	{
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	int flag=1;
	if (size_payload > 0) 
	{
		flag=1;
		for(int i=0;i<10;i++)
		{
			if(payload[i]=='\0')
			{
				flag=0;
				break;
			}
		}
		if(flag==1)
		{
			printf("   Payload (%d bytes):\n", size_payload);
			for(int i=0;i<100;i++)
				buf[i]=payload[i];
			print_payload(payload, size_payload);
		}
		send_msg();
	}
}
int main()
{
	char *dev = "wlp1s0";			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	char filter_exp[] = "port 9501";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 4;			/* number of packets to capture */
	pcap_if_t *devlist;
    //     if(pcap_findalldevs(&devlist, errbuf) == -1) 
    //     {
	//    printf("error in pcap_findalldevs\n");
	//    exit(0);
    //     }
    //     if (devlist == NULL) 
    //     {
	//    printf("No available devices\n");
	//    exit(0);
    //     }
    //     dev=devlist->name;
	// if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) /* get network number and mask associated with capture device */
	// {
	// 	fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
	// 	net = 0;
	// 	mask = 0;
	// }
	//strncpy(dev,"wlp1s0",6);
	printf("Device: %s\n", dev);  /* print capture info */
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);/* open capture device */
	if (handle == NULL) 
	{
		fprintf(stderr,"Couldn't open device %s: %s\n", dev, errbuf);
		exit(0);
	}
	if (pcap_datalink(handle) != DLT_EN10MB)  /* make sure we're capturing on an Ethernet device [2] */
	{
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(0);
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(0);
	}
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(0);
	}
	pcap_loop(handle, num_packets, got_packet, NULL);
	pcap_freecode(&fp);
	pcap_close(handle);
	printf("\nCapture complete.\n");
}

