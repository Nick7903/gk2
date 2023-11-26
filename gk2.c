#include <stdlib.h>
#include <stdio.h>

#define ROTR(x,n)	(x>>n) | (x<<(32-n))
#define ROTL(x,n)	(x<<n) | (x>>(32-n))

#define CH(x,y,z)	((x & y) ^ (~x & z))
#define MAJ(x,y,z)	(((x & y) ^ (x & z)) ^ (y & z))

#define BSIG0(x)	((ROTR(x,2)) ^ (ROTR(x,12))) ^ (ROTR(x,22))
#define BSIG1(x)	((ROTR(x,6)) ^ (ROTR(x,11))) ^ (ROTR(x,25))

#define SSIG0(x)	((ROTR(x,7)) ^ (ROTR(x,18))) ^ (x>>3)
#define SSIG1(x)	((ROTR(x,17)) ^ (ROTR(x,19))) ^ (x>>10)

#define uint32_MAX 	4294967295

typedef unsigned long long	uint64_t;
typedef unsigned int		uint32_t;
typedef unsigned char		uint8_t;


void printBits(uint32_t x)
{
	uint32_t y = x;

	for (uint32_t i = 0; i < sizeof(uint32_t)*8; i++)
	{
		printf("%d",(x&0x80000000?1:0));
		if (((i+1)%8)==0 && i < (sizeof(uint32_t)*8)-1) {printf(".");}
		x = x<<1;

	}
	
	printf("	0x");
	for (uint32_t i = 0; i < sizeof(uint32_t)*2; i++)
	{
		uint8_t z = ((y&0xf0000000)>>(sizeof(uint32_t)*7))+48; // Shift by 28
		y = y<<4;
		if (z > 57) {z = 'A' + z-58;}
		printf("%c",z);
	}

	printf("\n");
	return;
}

int sha224(char* string, char* hashOutput)
{
	// Get length of input
	uint64_t messagelength = 0;
	for (char* q = string; *q != '\0'; q++) {messagelength++;}
	
	// Create and initialize output messageblocks
	uint32_t blockamount = ((messagelength+9)/64)+1; // +8 because of MD strengthening, +1 for 0x80 byte
	uint8_t messageblocks[blockamount][64];
	for (uint8_t* a = (uint8_t*)messageblocks, * b = a+(blockamount*64); a < b; a++) {*a = 0;}

	// Move input into messageblocks
	int mbindex = 0;

	for (; mbindex < messagelength; mbindex++)
	{
		messageblocks[mbindex/64][mbindex-((mbindex/64)*64)] = string[mbindex];
	}

	// Set messagelength+1 to 0b10000000
	mbindex++;

	messageblocks[mbindex/64][mbindex-(mbindex/64)-1] = 0x80;

	// Insert messagelength as last 8 bytes (MD strengthening)
	for (uint32_t i = 0; i < 8; i++)
	{
		messageblocks[messagelength/64][64-i] = (uint8_t)((messagelength>>(i*8)) & 0xff);
	}

	uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	      	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};


	uint32_t a = 0xc1059ed8;
	uint32_t b = 0x367cd507;
	uint32_t c = 0x3070dd17;
	uint32_t d = 0xf70e5939;
	uint32_t e = 0xffc00b31;
	uint32_t f = 0x68581511;
	uint32_t g = 0x64f98fa7;
	uint32_t h = 0xbefa4fa4; // Irrelevant for sha224

	uint32_t a__ = 0;
	uint32_t b__ = 0;
	uint32_t c__ = 0;
	uint32_t d__ = 0;
	uint32_t e__ = 0;
	uint32_t f__ = 0;
	uint32_t g__ = 0;
	uint32_t h__ = 0;

	uint32_t W[64];

	// Process iteration
	for (uint32_t i = 0; i <= blockamount; i++)
	{
		
		// Prepare messageschedule (W)
		for (uint32_t t = 0; t <= 15; t++)
		{
			W[t] = (uint32_t)messageblocks[i][t];
		}

		for (uint32_t t = 16; t <= 63; t++)
		{
			W[t] = (SSIG1(W[t-2])) + W[t-7] + (SSIG0(W[t-15])) + W[t-16];
		}

		for (uint32_t t = 0; t <= 63; t++)
		{
			uint32_t T1 = (BSIG1(e)) + (CH(e,f,g)) + K[t] + W[t] + h;
			uint32_t T2 = (BSIG0(a)) + (MAJ(a,b,c));
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}

		a = a__ = a + a__;
		b = b__ = b + b__;
		c = c__ = c + c__;
		d = d__ = d + d__;
		e = e__ = e + e__;
		f = f__ = f + f__;
		g = g__ = g + g__;
		h = h__ = h + h__;
	}
	
	printBits(a);
	printBits(b);
	printBits(c);
	printBits(d);
	printBits(e);
	printBits(f);
	printBits(g);

	return 0;
}

int main(int argc, char** argv)
{	
	char hash[8];
	
	sha224("abc", hash);
	
	return 0;
}
