#include <stdlib.h>
#include <stdio.h>

#define ROTR(x,n) (x>>n) | (x<<(32-n))
#define ROTL(x,n) (x<<n) | (x>>(32-n))

typedef unsigned long long	uint64_t;
typedef unsigned int		uint32_t;
typedef unsigned char		uint8_t;


void printBits(uint32_t x) {
	for (uint32_t i=0;i<sizeof(uint32_t)*8;i++)
	{
		printf("%d",(x&0x80000000?1:0));
		if (((i+1)%8)==0) {printf(".");}
		x = x<<1;
	}
	printf("\n");
	return;
}

char* sha224(char* string)
{
	// Get length of input
	uint64_t messagelength = 0;
	for (char* q = string; *q != '\0'; q++) {messagelength++;}
	
	// Create and initialize output messageblocks
	uint8_t messageblocks[((messagelength+9)/64)+1][64]; // +8 because of MD strengthening, +1 for 0x80 byte
	for (uint8_t* a = (uint8_t*)messageblocks, * b = a+(((messagelength/64)+1)*64); a < b; a++) {*a = 0;}

	// Move input into messageblocks
	int mbindex = 0;

	for (; mbindex < messagelength; mbindex++)
	{
		messageblocks[mbindex/64][mbindex-((mbindex/64)*64)] = string[mbindex];
	}

	// Set messagelength+1 to 0b10000000
	mbindex++;

	messageblocks[mbindex/64][mbindex-(mbindex/64)] = 0x80;

	// Insert messagelength as last 8 bytes (MD strengthening)
	for (int i = 0; i < 8; i++)
	{
		messageblocks[messagelength/64][64-i] = (uint8_t)((messagelength>>(i*8)) & 0xff);
	}

	printf("messagelength:	%lld\n",messagelength);
	printBits(messageblocks[messagelength/64][59]);
	printBits(messageblocks[messagelength/64][60]);
	printBits(messageblocks[messagelength/64][61]);
	printBits(messageblocks[messagelength/64][62]);
	printBits(messageblocks[messagelength/64][63]);
	printBits(messageblocks[messagelength/64][64]);

	uint32_t H_0 = 0xc1059ed8;
	uint32_t H_1 = 0x367cd507;
	uint32_t H_2 = 0x3070dd17;
	uint32_t H_3 = 0xf70e5939;
	uint32_t H_4 = 0xffc00b31;
	uint32_t H_5 = 0x68581511;
	uint32_t H_6 = 0x64f98fa7;
	uint32_t H_7 = 0xbefa4fa4;
	
	return string;
}

int main(int argc, char** argv)
{	
	sha224(argv[1]);
	return 0;
}
