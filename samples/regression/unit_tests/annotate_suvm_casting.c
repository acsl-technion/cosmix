#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

extern void* __cosmix_suvm_annotation(void* ptr);

int main(int argc, char** argv) {
	size_t s = 12; // shouldn't fit threshold rule but we are going to annotate x
	//volatile __attribute__((annotate("suvm"))) int* x = (volatile int*) malloc(s);
	volatile int* x = (volatile int*) __cosmix_suvm_annotation(malloc(s));
	
	for (int i=0;i<s/sizeof(int);i++) {
		x[i] = i;
	}

    uintptr_t y = (uintptr_t)x;
    y+=8;
    int* z = (int*)y;
    printf("%d\n",*z);

	//free((void*)x);

	return 0;
}
