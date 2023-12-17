#include <stdio.h>
#include <stdint.h>

void printbits(const void* var)
{
    uint64_t x = *(uint64_t*) var;
    uint64_t y = *(uint64_t*) var;

	for (uint32_t i = 0; i < 64; i++)
	{
		printf("%d",(x&0x8000000000000000?1:0));
		if ((((i+1)%8)==0) && (i < 63)) {printf(".");}
		x = x<<1;
	}
	
	printf("    0x");
	for (uint32_t i = 0; i < 16; i++)
	{
		uint8_t z = ((y&0xf000000000000000)>>60)+48;
		y = y<<4;
		if (z > 57) {z = 'A' + z-58;}
		printf("%c",z);
	}

	printf("\n");
	return;
}

union
{
    uint8_t i8;
    uint16_t i16;
} a;

int main(void)
{
    a.i16 = 3000;

    printf("%hu\n", a.i8);

    printbits(&a.i8);
    printbits(&a.i16);

    return 0;
}