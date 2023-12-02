#include <stdlib.h>
#include <stdio.h>

#define ROTR(x,n)	(x>>n) | (x<<(32-n))
#define ROTL(x,n)	(x<<n) | (x>>(32-n))

#define CH(x,y,z)	((x & y) ^ (~x & z))
#define MAJ(x,y,z)	(((x & y) ^ (x & z)) ^ (y & z))

#define BSIG0(x)	((ROTR(x,2)) ^ (ROTR(x,13))) ^ (ROTR(x,22))
#define BSIG1(x)	((ROTR(x,6)) ^ (ROTR(x,11))) ^ (ROTR(x,25))

#define SSIG0(x)	((ROTR(x,7)) ^ (ROTR(x,18))) ^ (x>>3)
#define SSIG1(x)	((ROTR(x,17)) ^ (ROTR(x,19))) ^ (x>>10)

typedef unsigned long long	uint64_t;
typedef unsigned int		uint32_t;
typedef unsigned char		uint8_t;

typedef struct {

	uint8_t inputbuffer[64];
	uint32_t inputbuffersize;

	uint64_t inputbytes;

	uint32_t H[8];

} sha224_ctx;


void printbits(uint32_t x)
{
	uint32_t y = x;

	for (uint32_t i = 0; i < sizeof(uint32_t)*8; i++)
	{
		printf("%d",(x&0x80000000?1:0));
		if ((((i+1)%8)==0) && (i < (sizeof(uint32_t)*8)-1)) {printf(".");}
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

void sha224_init(sha224_ctx* ctx)
{
	ctx->inputbuffersize = 0;
	ctx->inputbytes = 0;

	ctx->H[0] = 0xc1059ed8;
	ctx->H[1] = 0x367cd507;
	ctx->H[2] = 0x3070dd17;
	ctx->H[3] = 0xf70e5939;
	ctx->H[4] = 0xffc00b31;
	ctx->H[5] = 0x68581511;
	ctx->H[6] = 0x64f98fa7;
	ctx->H[7] = 0xbefa4fa4;
}

void sha224_iterate(sha224_ctx* ctx)
{
	const uint32_t K[64] = {
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

	uint32_t W[64];

	uint32_t a = ctx->H[0];
	uint32_t b = ctx->H[1];
	uint32_t c = ctx->H[2];
	uint32_t d = ctx->H[3];
	uint32_t e = ctx->H[4];
	uint32_t f = ctx->H[5];
	uint32_t g = ctx->H[6];
	uint32_t h = ctx->H[7];
	
	
	for (uint32_t t = 0; t <= 15; t++)
	{
		W[t] = (uint32_t)((uint32_t)ctx->inputbuffer[t*4]<<24 | ctx->inputbuffer[t*4+1]<<16 | ctx->inputbuffer[t*4+2]<<8 | ctx->inputbuffer[t*4+3]);
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

	ctx->H[0] += a;
	ctx->H[1] += b;
	ctx->H[2] += c;
	ctx->H[3] += d;
	ctx->H[4] += e;
	ctx->H[5] += f;
	ctx->H[6] += g;
	ctx->H[7] += h;

	ctx->inputbuffersize = 0;

	return;
}

void sha224_append(sha224_ctx* ctx, uint8_t* input, size_t length)
{
	uint32_t next = 0;

	while (length)
	{
		while (length && (ctx->inputbuffersize < 64))
		{
			ctx->inputbuffer[ctx->inputbuffersize] = input[next];
			ctx->inputbuffersize++;
			ctx->inputbytes++;
			length--;
			next++;
		}

		if (ctx->inputbuffersize >= 64)
		{
			sha224_iterate(ctx);
		}
	}

	return;
}

void sha224_digest(sha224_ctx* ctx, uint8_t* output)
{
	// Set byte after input to 0b10000000
	ctx->inputbuffer[ctx->inputbuffersize] = 0x80;
	ctx->inputbuffersize++;

	// Make sure there is space for MD strengthening
	if ((64 - ctx->inputbuffersize) < 8)
	{
		for (uint32_t i = ctx->inputbuffersize; i < 64; i++)
		{
			ctx->inputbuffer[i] = 0;
		}

		sha224_iterate(ctx);
	}

	// Pad with zeroes until MD strengthening
	for (uint32_t i = ctx->inputbuffersize; i < 56; i++)
	{
		ctx->inputbuffer[i] = 0;
	}

	// Insert length as last 8 bytes (MD strengthening)
	for (uint32_t i = 0; i < sizeof(uint64_t); i++)
	{
		ctx->inputbuffer[63-i] = (uint8_t)((ctx->inputbytes*8)>>(i*8) & 0xff);
	}

	sha224_iterate(ctx);

	for (uint32_t i = 0; i < 7; i++)
	{
		for (uint32_t j = 0; j < sizeof(uint32_t)*2; j++)
		{
			uint8_t z = ((ctx->H[i]&0xf0000000)>>(sizeof(uint32_t)*7))+48; // Shift by 28
			ctx->H[i] = ctx->H[i]<<4;
			if (z > 57) {z = 'a' + z-58;}
			output[(i*8)+j] = z;
		}
	}

	return;
}

int main(int argc, char** argv)
{	
	char hash[57] = {0};
	hash[56] = '\0';

	size_t size = 0;
	while (argv[1][size] != '\0') {size++;}

	sha224_ctx myctx;

	sha224_init(&myctx);
	sha224_append(&myctx, (uint8_t*)argv[1], size);
	sha224_digest(&myctx, (uint8_t*)hash);

	printf("%s\n", hash);

	return 0;
}
