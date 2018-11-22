#include "libtrace.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <search.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sha.h>
#include <signal.h>

uint64_t count = 0;
struct bin {
	unsigned char hash[20];//20	SHA1 of the IP
	unsigned char hash_sub[20]; //20	SHA1 of the subnet. IPv4/24 IPv6/48
	uint32_t mss_quic;//4		Records the TCP MSS value or the UDP payload bytes that correspond to a QUIC version id
	uint32_t segment_size;//4
	uint8_t dscp;//1		Differentiated Services Code Point
	uint8_t opts;//1		The position of MSS in the options list
	unsigned char trans;//1		T-cp or U-dp
	uint16_t ip4 : 1;//bitflags	is ip4?
	uint16_t mf : 1;//		More fragments
	uint16_t df : 1;//		Don't fragment
	uint16_t ecn_ns : 1;//bitflags	9 TCP flags aka Control bits
	uint16_t fin : 1;
	uint16_t syn : 1;
	uint16_t rst : 1;
	uint16_t psh : 1;
	uint16_t ack : 1;
	uint16_t urg : 1;
	uint16_t ece : 1;
	uint16_t cwr : 1;
};
unsigned char salt1[30];
unsigned char salt2[30];

static void per_packet(libtrace_packet_t *packet, FILE *f, struct bin *record)
{
	uint16_t ether;
	void *ip_hdr;
	uint32_t rem;
	uint8_t proto;
	ip_hdr = trace_get_layer3(packet, &ether, &rem);
	if(ip_hdr == NULL) return;
	if(rem == NULL) return;
	libtrace_ip_t *ip;
	libtrace_ip6_t *ip6;
	void *hdr;
	uint8_t dscp;	
	SHA_CTX context;
	SHA1_Init(&context);
	switch(ether) {
		case TRACE_ETHERTYPE_IP:
			ip = (libtrace_ip_t *)ip_hdr;
			record->ip4 = 1;
			hdr = trace_get_payload_from_ip(ip, &proto, &rem);
			dscp = (ip->ip_tos);
			record->mf = 1&((ip->ip_off)>>5);//extract from 16bit fragment offset and flags field
			record->df = 1&((ip->ip_off)>>6);
			uint32_t ad = ntohl(ip->ip_src.s_addr);//hash the whole IP address
			SHA1_Update(&context, &ad, sizeof(uint32_t));
			SHA1_Update(&context, salt1, 30);
			SHA1_Final(record->hash, &context);
			
			ad = ad>>8;//hash the /24 subnet
			SHA1_Init(&context);
			SHA1_Update(&context, &ad, sizeof(uint32_t));
			SHA1_Update(&context, salt2, 30);
			SHA1_Final(record->hash_sub, &context);
			break;
		case TRACE_ETHERTYPE_IPV6:
			ip6 = (libtrace_ip6_t *)ip_hdr;
			record->ip4 = 0;
			dscp = ntohl(ip6->flow)>>20;
			dscp &= 255;
			hdr = trace_get_payload_from_ip6(ip6, &proto, &rem);
			
			SHA1_Update(&context, (ip6->ip_src.s6_addr),16);//hash the whole IP6 address
			SHA1_Update(&context, salt1, 30);
			SHA1_Final(record->hash, &context);

			unsigned char *ad6 = malloc(6);
			memcpy(ad6, (ip6->ip_src.s6_addr), 6);//hash the /48 subnet
			SHA1_Init(&context);
			SHA1_Update(&context, ad6, 6);
			SHA1_Update(&context, salt2, 30);
			SHA1_Final(record->hash_sub, &context);
			
			break;

		default:
			return;
	}
	libtrace_tcp_t *tcp;
	libtrace_udp_t *udp;
	unsigned char type, optlen, *data, *opt_ptr;
	int len;
	switch(proto) {
		case TRACE_IPPROTO_TCP:
			tcp = (libtrace_tcp_t *)hdr;
			record->dscp = dscp;
			record->trans = 'T';
			if (ether == TRACE_ETHERTYPE_IP) {
				record->segment_size = ntohs(ip->ip_len) - 4*(tcp->doff + ip->ip_hl);
			} else {
				record->segment_size =  ntohs(ip6->plen)- tcp->doff*4;
			}
			len = tcp->doff * 4 - sizeof(libtrace_tcp_t);
			if (len == 0) break;

			opt_ptr = (unsigned char *)tcp + sizeof(libtrace_tcp_t);
			uint8_t n = 0;
			uint32_t mss = 0;
			while(trace_get_next_option(&opt_ptr, &len, &type, &optlen, &data)) {
				n++;
				if (type != 2) break;
				for(int k = 0; k < optlen-2; k++){
					mss |= (data[k])<<(k*8);
				}
			mss = ntohs(mss);
			record->mss_quic = mss;//absence of mss option is recorded as mss == 0 and n == 0
			record->opts = n;	//an mss of 0 is stupid but recorded as mss == 0 and n >= 1. read_stats.c may need to be modified if this case occurs and needs to be filtered from the results
			}
			record->ecn_ns = tcp->ecn_ns;	//bunch of TCP flags
			record->fin = tcp->fin;
			record->syn = tcp->syn;
			record->rst = tcp->rst;
			record->psh = tcp->psh;
			record->ack = tcp->ack;
			record->urg = tcp->urg;
			record->ece = tcp->ece;
			record->cwr = tcp->cwr;
			break;
		case TRACE_IPPROTO_UDP:
			record->trans = 'U';
			record->dscp = dscp;
			udp = (libtrace_udp_t *)hdr;
			char *payload = trace_get_payload_from_udp(udp, &rem);
			if ( rem == 0) return;
			if (ntohs(udp->len)<21) return;
			uint32_t pay = (uint32_t)payload[12]<<24 | (uint32_t)payload[11]<<16 | (uint32_t)payload[10]<<8 | (uint32_t)payload[9];
			record->mss_quic = pay;//Assuming the payload were a QUIC packet, these 4 bytes refer to the version id field
			record->segment_size = ntohs(udp->len)-8;
			break;
		default:
			//Don't care about not TCP or UDP. Leaves most of the fields blank
			return;
	}
}

static void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet) {
        if (trace)
                trace_destroy(trace);
        if (packet)
                trace_destroy_packet(packet);
}

void cleaner(int sig) {
	exit(0);//makes sure buffer is flushed and files written on Ctrl+c

}
int main(int argc, char *argv[])
{
	signal(SIGINT, cleaner);

        libtrace_t *trace = NULL;
        libtrace_packet_t *packet = NULL;
	int snaplen = 150; //only collects first 150 bytes of each packet

        if (argc < 2) {
                fprintf(stderr, "Usage: %s inputURI\n", argv[0]);
                return 1;
        }

	packet = trace_create_packet();

        if (packet == NULL) {
                perror("Creating libtrace packet");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        trace = trace_create(argv[1]);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Opening trace file");
                libtrace_cleanup(trace, packet);
                return 1;
        }
	if (trace_config(trace,  TRACE_OPTION_SNAPLEN, &snaplen)== -1) {
		trace_perror(trace, "Setting snaplen");
		libtrace_cleanup(trace, packet);
		return 1;
	}
        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
                libtrace_cleanup(trace, packet);
                return 1;
        }
	FILE *s = fopen("salt1", "r");//reads the two salt files for the IP and subnet salting
	fread(salt1, 30, 1, s);
	fclose(s);
	s = fopen("salt2", "r");
	fread(salt2, 30, 1, s);
	fclose(s);
	char str_time[24];
	time_t now = time (0);
	strftime (str_time, sizeof(str_time), "%Y-%m-%d_%H:%M:%S.bin", gmtime(&now));//format time string for the binary logging filename
	
	FILE *f = fopen(str_time, "wb");
	if(f == NULL) {
		printf("fopen failed, full disk?\n");
		return -5;
	}
	FILE *stats = fopen("packet_stats", "a");
	char str_dropped[100];

	struct bin *record;
	record = malloc(sizeof(struct bin));
        while (trace_read_packet(trace,packet)>0) {
                per_packet(packet, f, record);
		
		count++;
		if(count > 1000000){ //every million packets rotate logs. 56MB logs. update the dropped packet stats
			fclose(f);
			now = time(0);
			strftime (str_time, sizeof(str_time), "%Y-%m-%d_%H:%M:%S.bin", gmtime(&now));
			snprintf(str_dropped, 100, "%s D%lu R%lu A%lu\n", str_time, trace_get_dropped_packets(trace), trace_get_received_packets(trace),trace_get_accepted_packets(trace));
			fwrite(str_dropped, strlen(str_dropped), 1, stats);	
			fflush(stats);
			f = fopen(str_time, "wb");
			if(f == NULL) {
				printf("fopen failed, full disk?\n");
				return -5;
			}
			count = 0;
		}
		fwrite(record, sizeof(struct bin), 1, f);
		memset(record->hash, 1, sizeof(record->hash));//clear the record after writing, not all fields are used for every packet so attempt to avoid noise from old data
		memset(record->hash_sub, 1, sizeof(record->hash_sub));
		record->mss_quic = 0; record->segment_size = 0; record->dscp = 0; 
		record->opts = 0; record->trans='X';
        }

	fclose(f);
	fclose(stats);
	free(record);

        libtrace_cleanup(trace, packet);
        return 0;
}
