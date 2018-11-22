#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <search.h>
#include <string.h>


struct bin {
	unsigned char hash[20];//20
	unsigned char hash_sub[20]; //20I
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
struct li {
	char *key;
	struct li *next;
};
int main(int argc, char *argv[]) {
	
	struct hsearch_data mss_table;
	struct hsearch_data dscp_table;
	memset((void *)&mss_table, 0, sizeof(mss_table));
	memset((void *)&dscp_table, 0, sizeof(dscp_table));
	hcreate_r(256, &dscp_table);
	hcreate_r(5000,&mss_table);
	struct li *mss_list;
	struct li *dscp_list;
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
			int *d = malloc(sizeof(int));
			*d = 1;
			snprintf(mss_int, 11, "%d", record.mss_quic);
			item_mss.key = strdup(mss_int);
			item_mss.data = d;
			if (hsearch_r(item_mss, FIND, &search_item, &mss_table)!= NULL){
				d = search_item->data;
				*d += 1;
				item_mss.data = d;
				printf("\nitem found of mss %s and %d\n", item_mss.key, *((int*)item_mss.data));
				hsearch_r(item_mss, ENTER, &search_item, &mss_table);
			}else {
				hsearch_r(item_mss, ENTER, &search_item, &mss_table);
				mss_head->key = item_mss.key;
				mss_head->next = malloc(sizeof(struct li));
				mss_head = mss_head->next;
				mss_head->next = NULL;
			}	
			char dscp_int[11];
			int *y = malloc(sizeof(int));
			*y = 1;
			snprintf(dscp_int, 11, "%d", record.dscp>>2);
			item_dscp.key = strdup(dscp_int);
			item_dscp.data = y;
			if (hsearch_r(item_dscp, FIND, &search_item, &dscp_table)!= NULL){
				y = search_item->data;
				*y += 1;
				item_dscp.data = y;
				printf("\nitem found of dscp %s and %d\n", item_dscp.key, *((int*)item_dscp.data));
				hsearch_r(item_dscp, ENTER, &search_item, &dscp_table);
			}else {
				hsearch_r(item_dscp, ENTER, &search_item, &dscp_table);
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
			int *y = malloc(sizeof(int));
			*y = 1;
			snprintf(dscp_int, 11, "%d", record.dscp>>2);
			item_dscp.key = strdup(dscp_int);
			item_dscp.data = y;
			if (hsearch_r(item_dscp, FIND, &search_item, &dscp_table)!= NULL){
				y = search_item->data;
				*y += 1;
				item_dscp.data = y;
				printf("\nitem found of dscp %s and %d\n", item_dscp.key, *((int*)item_dscp.data));
				hsearch_r(item_dscp, ENTER, &search_item, &dscp_table);
			}else {
				hsearch_r(item_dscp, ENTER, &search_item, &dscp_table);
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
	mss_head = mss_list;
	fprintf(stderr,"MSS	No.\n");
	while(1) {
		item_mss.key = mss_head->key;
		hsearch_r(item_mss, FIND, &search_item, &mss_table);
		fprintf(stderr,"%s %d\n", mss_head->key, *((int*)search_item->data));
		mss_head = mss_head->next;
		if (!mss_head->next) break;

	}
	dscp_head = dscp_list;
	fprintf(stderr,"DSCP	No.\n");
	while(1) {
		item_dscp.key = dscp_head->key;
		hsearch_r(item_dscp, FIND, &search_item, &dscp_table);
		fprintf(stderr,"%s %d\n", dscp_head->key, *((int*)search_item->data));
		dscp_head = dscp_head->next;
		if (!dscp_head->next) break;

	}
}
