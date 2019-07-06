#include <stdio.h>
#include "../../../include/common.h"

int main(int argc, char** argv) {
	size_t s = 0;
	volatile int* x = (volatile int*) malloc(s);
	
	//ASSERT(!IS_SUVM_PTR(x));

	volatile int* y = (volatile int*) realloc(x, s*2);

	//ASSERT(!IS_SUVM_PTR(y));

	volatile int* z = (volatile int*) calloc(2, s);

	//ASSERT(!IS_SUVM_PTR(z));

	return 0;
}
