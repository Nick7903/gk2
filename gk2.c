#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define ROTR(x,n) (x>>n) | (x<<(32-n))
#define ROTL(x,n) (x<<n) | (x>>(32-n))

void printBits(uint32_t x) {
	for (uint32_t i=0;i<sizeof(int32_t)*8;i++)
	{
		printf("%d",(x&0x80000000?1:0));
		x = x<<1;
	}
	printf("\n");
	return;
}

int main()
{	
	uint32_t H_0 = 0xc1059ed8;
	uint32_t H_1 = 0x367cd507;
	uint32_t H_2 = 0x3070dd17;
	uint32_t H_3 = 0xf70e5939;
	uint32_t H_4 = 0xffc00b31;
	uint32_t H_5 = 0x68581511;
	uint32_t H_6 = 0x64f98fa7;
	
	uint32_t a = 42;
	printBits(a);
	printBits(ROTL(a,6));
	printBits(ROTR(a,6));

	return 0;
}
