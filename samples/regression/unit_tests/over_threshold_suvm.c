#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "../../../include/common.h"

int main(int argc, char** argv) {
	size_t s = 16384;
	volatile int* x = (volatile int*) malloc(s);

	volatile int* y = (volatile int*) realloc((void*)x, s*2);

	volatile int* z = (volatile int*) calloc(2, s);
	
	return z[0];
}
