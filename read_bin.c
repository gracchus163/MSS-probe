#include <stdio.h>
#include <inttypes.h>
#include <search.h>


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
int main(int argc, char *argv[]) {
	
	struct bin record;		
	FILE *f;
	f = fopen(argv[1],"rb");
	uint64_t i = 0;
	uint64_t t = 0;
	uint64_t u = 0;
	int bin_len = sizeof(record);	
	printf("%d",bin_len);

//	while(fread(record.hash,20 ,1,f)>0){
//		fread(&record.mss_quic,4 ,1,f); 
//		fread(&record.segment_size,4 ,1,f); 
//		fread(&record.dscp,1 ,1,f); 
//		fread(&record.opts,1 ,1,f);
//		fread(&record.trans,1,1,f);
//		fread(&record.packing,1,1,f);
	while(fread(&record, bin_len, 1, f)>0){
		printf("%lu. ", ++i);
		printf("%s ", record.ip4 ? "IPv4" : "IPv6");
		if (record.trans == 'T') {
			printf("tcp ");
			printf("0x%02x%02x%02x%02x", record.hash[0], record.hash[1], record.hash[2], record.hash[3]);
			printf(" subnet 0x%02x%02x%02x%02x", record.hash_sub[0], record.hash_sub[1], record.hash_sub[2], record.hash_sub[3]);
			printf(" dscp %d mss %d mss pos:%d size %d ", record.dscp>>2, record.mss_quic, record.opts, record.segment_size);
			printf("ecn_ns %u fin %u syn %u rst %u psh %u ack %u urg %u ece %u cwr %u ", record.ecn_ns, record.fin, record.syn, record.rst, record.psh, record.ack, record.urg, record.ece, record.cwr);

		} else if (record.trans=='U') {
			printf("udp ");
			printf(" 0x%02x%02x%02x%02x", record.hash[0], record.hash[1], record.hash[2], record.hash[3]);
			printf(" subnet 0x%02x%02x%02x%02x", record.hash_sub[0], record.hash_sub[1], record.hash_sub[2], record.hash_sub[3]);
			printf(" dscp %d QUIC 0x%08x size %d ", record.dscp>>2,record.mss_quic, record.segment_size);

		}else {
			printf("neither");
		}
		if (record.ip4) printf("DF %u MF %u", record.df, record.mf);
		printf("\n");

	}
	fclose(f);
}
