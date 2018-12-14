#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#define __USE_GNU
#define _GNU_SOURCE
#include <search.h>
#include <string.h>


struct bin {
	unsigned char hash[20];//20		SHA1 of the IP
	unsigned char hash_sub[20]; //20	SHA1 of the subnet. IPv4/24 IPv6/48
	uint32_t mss_quic;//4			Records the TCP MSS value of the UDP payload bytes that correspond to a QUIC version id
	uint32_t segment_size;//4		
	uint8_t dscp;//1			Differentiated Services Code Point
	uint8_t opts;//1			The position of MSS in the options list
	unsigned char trans;//1			T-cp or U-dp
	uint16_t ip4 : 1;//bitflags		is ip4?
	uint16_t mf : 1;//			More fragments
	uint16_t df : 1;//			Don't fragment
	uint16_t ecn_ns : 1;//bitflags		9 TCP flags aka Control bits
	uint16_t fin : 1;
	uint16_t syn : 1;
	uint16_t rst : 1;
	uint16_t psh : 1;
	uint16_t ack : 1;
	uint16_t urg : 1;
	uint16_t ece : 1;
	uint16_t cwr : 1;
};
struct li {
	char *key;
	struct li *next;
};
int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Give bin files as arguments\n");
		return -1;
	}
	int verbose = 0; //print stuff
	if (strcmp(argv[1], "-v")  == 0) {
		verbose = 1;
	}
	struct hsearch_data *mss_table;  
	struct hsearch_data *dscp_table;  //setup hash tables
	struct hsearch_data *ip_table;
	struct hsearch_data *size_table;
	mss_table = calloc(1, sizeof(struct hsearch_data));
	dscp_table = calloc(1, sizeof(struct hsearch_data));
	ip_table = calloc(1, sizeof(struct hsearch_data));
	size_table = calloc(1, sizeof(struct hsearch_data));
	
	hcreate_r(256, dscp_table);	//full range of possible dscp values
	hcreate_r(5000,mss_table);	//possible range is 0-65536. seems unrealistic, can increase the table size otherwise
	hcreate_r(16000000, ip_table); // /24 subnet
	hcreate_r(65536, size_table); // /24 subnet
	struct li *mss_list;
	struct li *dscp_list;//linked lists to store occurences in the hash table
	struct li *ip_list;
	struct li *size_list;
	mss_list = malloc(sizeof(struct li));
	dscp_list = malloc(sizeof(struct li));
	ip_list = malloc(sizeof(struct li));
	size_list = malloc(sizeof(struct li));
	struct li *mss_head = mss_list;
	struct li *dscp_head = dscp_list;
	struct li *ip_head = ip_list;
	struct li *size_head = size_list;
	
	ENTRY item_dscp;
	ENTRY item_mss;
	ENTRY item_ip;
	ENTRY item_size;
	ENTRY *search_item;
	struct bin record;		
	uint64_t i = 0;
	uint64_t t = 0;
	uint64_t u = 0;
	uint64_t ip_count = 0;
	uint64_t syn_count = 0;
	uint64_t bad_syn_count = 0;
	uint64_t mf_count = 0;
	int bin_len = sizeof(record);	

	FILE *f;

for (int v = (verbose+1); v < argc; v++) {
	f = fopen(argv[v],"rb");
	while(fread(&record, bin_len, 1, f)>0){
	//	if (record.ip4) continue;
		i++;
		if (verbose) {
			printf("%lu. ", i);
			printf("%s ", record.ip4 ? "IPv4" : "IPv6");
		}
		if (record.trans == 'T') {
			t++;
			if (record.syn) syn_count++;
				char *ip_buf = malloc(41);
				uint8_t *in = malloc(sizeof(uint8_t));
				uint8_t *temp;
				*in = (record.dscp>>2);
				for (int q = 0; q < 20; q++) {
					sprintf(ip_buf+(2*q), "%02x", record.hash_sub[q]);
				}
				*(ip_buf+40) = 0;
				item_ip.key =ip_buf;
				item_ip.data = in;
				//printf("%s\n", ip_buf);
				if (hsearch_r(item_ip, FIND, &search_item, ip_table)){//ip already in the table,grab occurence value and update by 1
					temp = search_item->data;
			//		printf("temp %u\n", *temp);
					if (*in != *temp) {
						printf("Dscp>>2 change from %u to %u %s\n", *temp, *in, ip_buf);
					//	search_item->data = in;
						*temp = *in;
					}
					free(in);
					free(ip_buf);
				}else {//new ip occurence, add it to the table and iterate the linked list
					if (!hsearch_r(item_ip, ENTER, &search_item, ip_table)) perror("ip entry: ");
					ip_head->key = item_ip.key;
					ip_head->next = malloc(sizeof(struct li));
					ip_head = ip_head->next;
					ip_head->next = NULL;
					ip_count++;
				}	
			if (verbose) {
				printf("tcp ");
				printf("0x%02x%02x%02x%02x", record.hash[0], record.hash[1], record.hash[2], record.hash[3]);
				printf(" subnet 0x%02x%02x%02x%02x", record.hash_sub[0], record.hash_sub[1], record.hash_sub[2], record.hash_sub[3]);
				printf(" dscp %d mss %d mss pos:%d size %d ", record.dscp>>2, record.mss_quic, record.opts, record.segment_size);
				printf("ecn_ns %u fin %u syn %u rst %u psh %u ack %u urg %u ece %u cwr %u ", record.ecn_ns, record.fin, record.syn, record.rst, record.psh, record.ack, record.urg, record.ece, record.cwr);
			}
		} else if (record.trans=='U') {
			u++;
			if (verbose) {
				printf("udp ");
				printf(" 0x%02x%02x%02x%02x", record.hash[0], record.hash[1], record.hash[2], record.hash[3]);
				printf(" subnet 0x%02x%02x%02x%02x", record.hash_sub[0], record.hash_sub[1], record.hash_sub[2], record.hash_sub[3]);
				printf(" dscp %u QUIC 0x%08x size %u ", record.dscp>>2,record.mss_quic, record.segment_size);
			}
		}else if (verbose) {
			printf("neither");
		}
		if (verbose) {
			if (record.ip4) printf("DF %u MF %u", record.df, record.mf);
			printf("\n");
		}
	}
	fclose(f);
}//end for
	//loop over lists to get the keys stored in the table and their values
	fprintf(stderr, "Total: %lu\n", i);
	fprintf(stderr, "TCP: %lu\n", t);
	fprintf(stderr, "UDP: %lu\n", u);
	fprintf(stderr, "MF: %lu\n", mf_count);
	fprintf(stderr, "SYNs: %lu\n", syn_count);
	fprintf(stderr, "Bad SYNs: %lu\n", bad_syn_count);
}
