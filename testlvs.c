/*
 *
 * TESTLVS	Test client for Linux Virtual Server
 *
 *		This  program  allows  testing  of  the  LVS
 *		director  throughput by sending packets from
 *		different source addresses.
 *
 * Author:	Julian Anastasov <ja@ssi.bg>, September 2000
 * 
 *		Released under the GPL version 2
 *
 *
 */


#define	VERSION "0.1"

/*
 * Example:
 *
 *	testlvs 192.168.0.1:80 -packets 10000
 *
 *
 *
 * Notes:
 *
 *	- This program can be run only from RUID=0
 *
 *	- Sending of packets longer than MTU is not allowed,
 *	i.e. we don't test IP defragmentation
 *
 *
 * History:
 *
 *	17-SEP-2000
 *			- Version 0.1
 *
 *
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define __u8		u_int8_t
#define __u16		u_int16_t
#define __u32		u_int32_t

char			*srcnet = "10.0.0.1";
char			*vip = 0;
int			port = 0;
int			npackets = 1;
int			ttl = 2;
int			srcnum = 254;
int			psize = 1400;
int			proto = IPPROTO_TCP;
int			random_src = 0;
int			dump = 0;

int			sock;
char			*pack;
struct iphdr		*iph;
struct udphdr		*uh;
struct tcphdr		*th;
struct sockaddr_in	target;
__u32			srcval;
__u16			sum0;

/* TCP/UDP pseudo header */
struct {
	__u32	saddr, daddr;
	__u8	zero, proto;
	__u16	length;
} tu;


__u16 csum_partial(__u16 *p, int l, __u16 oldsum)
{
	union {
		__u8	b;
		__u16	w;
	} u;
	__u32 sum = 0;

	while (l >= 2) {
		sum += *p ++;
		l -= 2;
	}
	if (l) {
		u.w = 0;
		u.b = *((__u8 *) p);
		sum += u.w;
	}
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum += oldsum;
	return sum + (sum >> 16);
}

void initialize(void)
{
__u16 dsz;
int sz, ofs, i, j;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		perror("socket(): Unable to create socket");
		exit(1);
	}

	srand(time(0));

	sz = psize;
	dsz = htons(psize - sizeof(struct iphdr));
	pack = malloc(sz);
	if (!pack) {
		errno = ENOMEM;
		perror("malloc()");
		exit(1);
	}
	memset(pack,0,sz);

	/* Setup IP header */

	iph = (struct iphdr *) pack;
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = htons(psize);
	iph->id = htons(getpid() & 0xFFFF);
	iph->frag_off = 0;
	iph->ttl = ttl;
	iph->protocol = proto;
	iph->saddr = htonl(srcval);
	iph->daddr = inet_addr(vip);

	/* Setup target */

	memset(&target,0,sizeof(target));
	target.sin_family = AF_INET;
	target.sin_port = htons(port);
	target.sin_addr.s_addr = iph->daddr;

	/* Setup TCP/UDP pseudo header */

	memset(&tu,0,sizeof(tu));
	//tu.saddr = iph->saddr;
	tu.daddr = iph->daddr;
	tu.proto = proto;
	tu.length = dsz;

	/* Setup protocol header */

	switch (proto) {

	case IPPROTO_UDP:
		uh = (struct udphdr *) (iph+1);
		uh->source = htons(5000);
		uh->dest = htons(port);
		uh->len = dsz;
		uh->check = 0;
		ofs = sizeof(struct udphdr);
		break;

	case IPPROTO_TCP:
		th = (struct tcphdr *) (iph+1);
		th->source = htons(5000);
		th->dest = htons(port);
		th->syn = 1;
		th->doff = sizeof(struct tcphdr) / 4;
		//th->window = htons(32120);
		th->check = 0;
		ofs = sizeof(struct tcphdr);
		break;
	}

	/* Initialize data */

	ofs += sizeof(struct iphdr);
	for (i = 0x20, sz = psize - ofs, j = ofs; sz > 0; sz--) {
		pack[j ++] = i;
		if (++i >= 0x7E) i = 0x20;
	}

	/* Proto + Data checksum */

	ofs = sizeof(struct iphdr);
	sum0 = csum_partial((__u16 *) (pack+ofs),psize-ofs,0);
}

int send_packets(void)
{
__u32 saddr;
__u16 sum;


	fprintf(stderr,"Sending %d-byte %s packets from %s[%d] to %s:%d\n",
		psize,
		IPPROTO_TCP==proto?"TCP":"UDP",
		srcnet,srcnum,vip,port);

	saddr = srcval;

	loop:

	saddr = htonl(saddr);

	tu.saddr = saddr;
	iph->saddr = saddr;

	/* IP header checksum */

	iph->check=0;
	iph->check = ~csum_partial((__u16 *) iph, iph->ihl*4, 0);

	/* Protocol checksum */

	sum = ~csum_partial((__u16 *) &tu,sizeof(tu),sum0);

	switch (proto) {
	case IPPROTO_UDP:
		uh->check = sum;
		if (!uh->check) uh->check = 0xFFFF;
		break;
	case IPPROTO_TCP:
		th->check = sum;
		break;
	}

	if (dump) {

		fwrite(pack,1,psize,stdout);

	} else if (sendto(sock,pack,psize,0,
		&target,sizeof(target)) < 0) {

		perror("send()");
		return 1;

	}

	if (npackets) {
		if (!--npackets) return 0;
	}

	if (random_src) {
		saddr = srcval + rand() % srcnum;
	} else {
		saddr = ntohl(saddr) + 1;
		if (saddr >= srcval + srcnum) saddr = srcval;
	}

	goto loop;
}

void print_help(void)
{
	fprintf(stderr,
	       "\n"
	       "Test client for LVS, version " VERSION "\n"
	       "\n"
	       "Usage: [options] VIP:port\n"
	       "\n"
	       "-srcnet A.B.C.D		First source address (%s)\n"
	       "-srcnum n		Number of source addresses to use (%d)\n"
	       "-random			Select random saddr in the range\n"
	       "-packets		Number of packets to send, 0=no limit (%d)\n"
	       "-ttl n			IP TTL (%d)\n"
	       "-size n			UDP packet size <= MTU (%d)\n"
	       "-udp			Send UDP packets\n"
	       "-tcp			Send TCP SYN packets (def)\n"
	       "-dump			Dump the packets to stdout\n"
	       ,srcnet, srcnum, npackets, ttl, psize);


	exit(1);
}

int main(int argc, char *argv[])
{
	int i, v;
	char *cp;

	setuid(getuid());

	/* Parse arguments */

	for (i = 1; i < argc; i++) {

		if ('-' != *argv[i]) {
			/* VIP:VPORT */
			if (vip) print_help();
			cp = strchr(argv[i],':');
			if (!cp) print_help();
			port = atoi(cp+1);
			if (port <= 0 || port >= 65535) print_help();
			*cp = 0;
			vip = argv[i];
			continue;
		}
		if (!strcmp(argv[i],"-srcnet")) {
			/* Range for the source addresses */
			if (++i >= argc) print_help();
			srcval = inet_addr(argv[i]);
			if (-1L == srcval) print_help();
			srcnet = argv[i];
			continue;
		}
		if (!strcmp(argv[i],"-srcnum")) {
			/* Number of the source addresses */
			if (++i >= argc) print_help();
			v = atoi(argv[i]);
			if (v < 1 || v > (1<<24)) print_help();
			srcnum = v;
			continue;
		}
		if (!strcmp(argv[i],"-packets")) {
			/* Packets to send */
			if (++i >= argc) print_help();
			v = atoi(argv[i]);
			if (v < 0) print_help();
			npackets = v;
			continue;
		}
		if (!strcmp(argv[i],"-random")) {
			/* Select random source address	*/
			/* in the range. By default,	*/
			/* all source addresses are	*/
			/* cycled			*/
			random_src = 1;
			continue;
		}
		if (!strcmp(argv[i],"-ttl")) {
			/* IP Time To Live */
			if (++i >= argc) print_help();
			v = atoi(argv[i]);
			if (v < 1 || v > 255) print_help();
			ttl = v;
			continue;
		}
		if (!strcmp(argv[i],"-size")) {
			/* Packet size to use for the	*/
			/* UDP datagram			*/
			if (++i >= argc) print_help();
			v = atoi(argv[i]);
			if (v < 1 || v > 65535) print_help();
			psize = v;
			continue;
		}
		if (!strcmp(argv[i],"-udp")) {
			proto = IPPROTO_UDP;
			continue;
		}
		if (!strcmp(argv[i],"-tcp")) {
			proto = IPPROTO_TCP;
			continue;
		}
		if (!strcmp(argv[i],"-dump")) {
			/* Dump packet to stdout,	*/
			/* default is to send packet	*/
			dump = 1;
			continue;
		}
		print_help();
	}

	if (!vip) print_help();
	srcval = ntohl(inet_addr(srcnet));
	if (IPPROTO_TCP == proto) {
		/* We send SYN packets without data */
		psize = sizeof(struct iphdr) + sizeof(struct tcphdr);
	}

	initialize();

	return send_packets();
}
