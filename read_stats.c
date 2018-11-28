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
	struct hsearch_data *mss_table;  
	struct hsearch_data *dscp_table;  //setup 2 hash tables
	mss_table = calloc(1, sizeof(struct hsearch_data));
	dscp_table = calloc(1, sizeof(struct hsearch_data));
	//memset((void *)&mss_table, 0, sizeof(mss_table));
	//memset((void *)&dscp_table, 0, sizeof(dscp_table));
	
	hcreate_r(256, dscp_table);	//full range of possible dscp values
	hcreate_r(5000,mss_table);	//possible range is 0-65536. seems unrealistic, can increase the table size otherwise
	struct li *mss_list;
	struct li *dscp_list;//linked lists to store occurences in the hash table
	mss_list = malloc(sizeof(struct li));
	dscp_list = malloc(sizeof(struct li));
	struct li *mss_head = mss_list;
	struct li *dscp_head = dscp_list;
	
	ENTRY item_dscp;
	ENTRY item_mss;
	ENTRY *search_item;
	struct bin record;		
	FILE *f;
	f = fopen(argv[1],"rb");
	uint64_t i = 0;
	uint64_t t = 0;
	uint64_t u = 0;
	int bin_len = sizeof(record);	

	while(fread(&record, bin_len, 1, f)>0){
		printf("%lu. ", ++i);
		printf("%s ", record.ip4 ? "IPv4" : "IPv6");
		if (record.trans == 'T') {
			printf("tcp ");
			printf("0x%02x%02x%02x%02x", record.hash[0], record.hash[1], record.hash[2], record.hash[3]);
			printf(" subnet 0x%02x%02x%02x%02x", record.hash_sub[0], record.hash_sub[1], record.hash_sub[2], record.hash_sub[3]);
			printf(" dscp %d mss %d mss pos:%d size %d ", record.dscp>>2, record.mss_quic, record.opts, record.segment_size);
			printf("ecn_ns %u fin %u syn %u rst %u psh %u ack %u urg %u ece %u cwr %u ", record.ecn_ns, record.fin, record.syn, record.rst, record.psh, record.ack, record.urg, record.ece, record.cwr);
			char mss_int[11];
			uint64_t *d = malloc(sizeof(uint64_t));
			*d = 1;
			snprintf(mss_int, 11, "%d", record.mss_quic);
			item_mss.key = strdup(mss_int);
			item_mss.data = d;
			if (hsearch_r(item_mss, FIND, &search_item, mss_table)!= NULL){//mss already in the table,grab occurence value and update by 1
				free(d);
				free(item_mss.key);
				d = search_item->data;
				*d += 1;
			//	item_mss.data = d;
			//	hsearch_r(item_mss, ENTER, &search_item, mss_table);
			}else {//new mss occurence, add it to the table and iterate the linked list
				hsearch_r(item_mss, ENTER, &search_item, mss_table);
				mss_head->key = item_mss.key;
				mss_head->next = malloc(sizeof(struct li));
				mss_head = mss_head->next;
				mss_head->next = NULL;
			}	
			char dscp_int[11];
			uint64_t *y = malloc(sizeof(uint64_t));
			*y = 1;
			snprintf(dscp_int, 11, "%d", record.dscp>>2);
			item_dscp.key = strdup(dscp_int);
			item_dscp.data = y;
			if (hsearch_r(item_dscp, FIND, &search_item, dscp_table)!= NULL){//dscp already found in table, grab occurence and update by 1
				free(y);
				free(item_dscp.key);
				y = search_item->data;
				*y += 1;
				//item_dscp.data = y;
				//hsearch_r(item_dscp, ENTER, &search_item, dscp_table);
			}else {//new dscp occurence, add it to the table and iterate the linked list
				hsearch_r(item_dscp, ENTER, &search_item, dscp_table);
				dscp_head->key = item_dscp.key;
				dscp_head->next = malloc(sizeof(struct li));
				dscp_head = dscp_head->next;
				dscp_head->next = NULL;
			}	
		} else if (record.trans=='U') {
			printf("udp ");
			printf(" 0x%02x%02x%02x%02x", record.hash[0], record.hash[1], record.hash[2], record.hash[3]);
			printf(" subnet 0x%02x%02x%02x%02x", record.hash_sub[0], record.hash_sub[1], record.hash_sub[2], record.hash_sub[3]);
			printf(" dscp %d QUIC 0x%08x size %d ", record.dscp>>2,record.mss_quic, record.segment_size);

			char dscp_int[11];
			uint64_t *y = malloc(sizeof(uint64_t));
			*y = 1;
			snprintf(dscp_int, 11, "%d", record.dscp>>2);
			item_dscp.key = strdup(dscp_int);
			item_dscp.data = y;
			if (hsearch_r(item_dscp, FIND, &search_item, dscp_table)!= NULL){
				free(y);
				free(item_dscp.key);
				y = search_item->data;
				*y += 1;
			}else {
				hsearch_r(item_dscp, ENTER, &search_item, dscp_table);
				dscp_head->key = item_dscp.key;
				dscp_head->next = malloc(sizeof(struct li));
				dscp_head = dscp_head->next;
				dscp_head->next = NULL;
			}	
		}else {
			printf("neither");
		}
		if (record.ip4) printf("DF %u MF %u", record.df, record.mf);
		printf("\n");

	}
	fclose(f);
	//loop over lists to get the keys stored in the table and their values
	mss_head = mss_list;
	fprintf(stderr,"MSS	No.\n");
	while(mss_head->next) {
		item_mss.key = mss_head->key;
		hsearch_r(item_mss, FIND, &search_item, mss_table);
		fprintf(stderr,"%s	%lu\n", mss_head->key, *((uint64_t*)search_item->data));
		mss_head = mss_head->next;
	}
	dscp_head = dscp_list;
	fprintf(stderr,"DSCP	No.\n");
	while(dscp_head->next) {
		item_dscp.key = dscp_head->key;
		hsearch_r(item_dscp, FIND, &search_item, dscp_table);
		fprintf(stderr,"%s	%lu\n", dscp_head->key, *((uint64_t*)search_item->data));
		dscp_head = dscp_head->next;
	}
}
