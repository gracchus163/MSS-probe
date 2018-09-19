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
	unsigned char hash[20];//20
	unsigned char hash_sub[20]; //20
	uint32_t mss_quic;//4
	uint32_t segment_size;//4
	uint8_t dscp;//1
	uint8_t opts;//1
	unsigned char trans;//1
	uint16_t ip4 : 1;
	uint16_t mf : 1;
	uint16_t df : 1;
	uint16_t ecn_ns : 1;
	uint16_t fin : 1;
	uint16_t syn : 1;
	uint16_t rst : 1;
	uint16_t psh : 1;
	uint16_t ack : 1;
	uint16_t urg : 1;
	uint16_t ece : 1;
	uint16_t cwr : 1;
};

static void per_packet(libtrace_packet_t *packet, FILE *f, struct bin *record)
{
	trace_set_capture_length(packet, 120); //snaplen
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
//	char str[INET6_ADDRSTRLEN];
	SHA_CTX context;
	SHA1_Init(&context);
	switch(ether) {
		case TRACE_ETHERTYPE_IP:
			ip = (libtrace_ip_t *)ip_hdr;
			record->ip4 = 1;
			////printf("IP %s ", inet_ntop(AF_INET, &(ip->ip_src.s_addr), str, sizeof(str)));
			hdr = trace_get_payload_from_ip(ip, &proto, &rem);
			dscp = (ip->ip_tos);
			//record->opts = (ip->ip_off)>>5;
			record->mf = 1&((ip->ip_off)>>5);
			record->df = 1&((ip->ip_off)>>6);
	//		printf("%d %d\n", ip->ip_off, record->opts);
			uint32_t ad = ntohl(ip->ip_src.s_addr);
			SHA1_Update(&context, &ad, sizeof(uint32_t));
			SHA1_Update(&context, "SUPER secure salt", sizeof("SUPER secure salt"));
			SHA1_Final(record->hash, &context);//build
			
			ad = ad>>8;
			SHA1_Init(&context);
			SHA1_Update(&context, &ad, sizeof(uint32_t));//additional hash of /24
			SHA1_Update(&context, "SUPER secure salt number2", sizeof("SUPER secure salt number2"));
			SHA1_Final(record->hash_sub, &context);//build
			break;
		case TRACE_ETHERTYPE_IPV6:
			ip6 = (libtrace_ip6_t *)ip_hdr;
			record->ip4 = 0;
			////printf("IP6 %s ", inet_ntop(AF_INET6, &(ip6->ip_src.s6_addr), str, sizeof(str)));
			dscp = ntohl(ip6->flow)>>20;
			dscp &= 255;
			hdr = trace_get_payload_from_ip6(ip6, &proto, &rem);
			
			SHA1_Update(&context, (ip6->ip_src.s6_addr),16);
			SHA1_Update(&context, "SUPER secure salt", sizeof("SUPER secure salt"));
			SHA1_Final(record->hash, &context);//build

			unsigned char *ad6 = malloc(7);
			memcpy(ad6, (ip6->ip_src.s6_addr), 7);
			//printf("ip6: %d ip6# %d\n", *ad6, *ip6->ip_src.s6_addr);
			SHA1_Init(&context);
			SHA1_Update(&context, ad6, 7);
			SHA1_Update(&context, "SUPER secure salt number2", sizeof("SUPER secure salt number2"));
			SHA1_Final(record->hash_sub, &context);//build
			
			break;

		default:
			return;
	}
	//printf("DSCP: %d ", dscp);
	libtrace_tcp_t *tcp;
	libtrace_udp_t *udp;
	unsigned char type, optlen, *data, *opt_ptr;
	int len;
	switch(proto) {
		case TRACE_IPPROTO_TCP:
			tcp = (libtrace_tcp_t *)hdr;
			//dscp |= 1<<7; //set top bit if TCP
			record->dscp = dscp;//build
			//printf("TCP ");	
			record->trans = 'T';
			if (ether == TRACE_ETHERTYPE_IP) {
				//printf("payload: %d ", ntohs(ip->ip_len) - 4*(tcp->doff + ip->ip_hl));
				record->segment_size = ntohs(ip->ip_len) - 4*(tcp->doff + ip->ip_hl);//build

			} else {

				//printf("payload: %d ", ntohs(ip6->plen)- tcp->doff*4);
				record->segment_size =  ntohs(ip6->plen)- tcp->doff*4;//build
			}
			len = tcp->doff * 4 - sizeof(libtrace_tcp_t);
			if (len == 0) break;

			opt_ptr = (unsigned char *)tcp + sizeof(libtrace_tcp_t);
			uint8_t n = 0;
			while(trace_get_next_option(&opt_ptr, &len, &type, &optlen, &data)) {
				n++;
				if (type != 2) break;
				uint32_t mss = 0;
				for(int k = 0; k < optlen-2; k++){
					mss |= (data[k])<<(k*8);
				}
			mss = ntohs(mss);
			record->mss_quic = mss;//build
			record->opts = n;
			}
			record->ecn_ns = tcp->ecn_ns;
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
			//printf("UDP ");
			//dscp |= 1<<6; //set 2nd top bit if UDP
			record->trans = 'U';
			record->dscp = dscp;//build
			udp = (libtrace_udp_t *)hdr;
			char *payload = trace_get_payload_from_udp(udp, &rem);
			if ( rem == 0) return;
			if (ntohs(udp->len)<21) return;
			uint32_t pay = (uint32_t)payload[12]<<24 | (uint32_t)payload[11]<<16 | (uint32_t)payload[10]<<8 | (uint32_t)payload[9];
			//printf("quic: 0x%02x%02x%02x%02x ", (uint8_t)payload[9],(uint8_t) payload[10], (uint8_t)payload[11], (uint8_t)payload[12]);
			//printf("mangled quic: 0x%x ", pay);
			//printf("payload: %d ", ntohs(udp->len)-8);
			record->mss_quic = pay;//build
			record->segment_size = ntohs(udp->len)-8;
			break;

		default:
			//printf("un protocol");
			return;
	}

	//printf("DSCP_proto: %d ", dscp);

}

static void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet) {

        /* It's very important to ensure that we aren't trying to destroy
         * a NULL structure, so each of the destroy calls will only occur
         * if the structure exists */
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

        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
                libtrace_cleanup(trace, packet);
                return 1;
        }
	char str_time[24];
	time_t now = time (0);
	strftime (str_time, sizeof(str_time), "%Y-%m-%d %H:%M:%S.bin", gmtime(&now));
	
	FILE *f = fopen(str_time, "wb");
	if(f == NULL) return -5;

	struct bin *record;
	record = malloc(sizeof(struct bin));
        while (trace_read_packet(trace,packet)>0) {
                per_packet(packet, f, record);
		//printf(" dscp: %d", record->dscp);
		//printf("\n");
		
		count++;
		if(count > 1000000){ //every million packets rotate logs. appropriate number? 31MB logs
			fclose(f);
			now = time(0);
			strftime (str_time, sizeof(str_time), "%Y-%m-%d %H:%M:%S.bin", gmtime(&now));
	
			f = fopen(str_time, "wb");
			if(f == NULL) return -5
			count = 0;
		}
		//record->mss_quic = 0xdeadbeef; record->segment_size = 0xfeed5eed; record->dscp = 0xbb;
		fwrite(record, sizeof(struct bin), 1, f);
		//fflush(f);
		memset(record->hash, 1, sizeof(record->hash));
		memset(record->hash_sub, 1, sizeof(record->hash_sub));
		record->mss_quic = 0; record->segment_size = 0; record->dscp = 0; 
		record->opts = 0; record->trans='X';
        }

	fclose(f);
	free(record);
        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }

	//printf("Packet Count = %" PRIu64 "\n", count);

        libtrace_cleanup(trace, packet);
        return 0;
}
