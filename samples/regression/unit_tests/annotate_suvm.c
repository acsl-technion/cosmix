#include <stdio.h>
#include <stdlib.h>

volatile int* g_test1 = 0;
volatile int* g_test2 = 0;

extern void* __cosmix_suvm_annotation(void* ptr);

int main(int argc, char** argv) {
	size_t s = 12; // shouldn't fit threshold rule but we are going to annotate x
	//volatile __attribute__((annotate("suvm"))) int* x = (volatile int*) malloc(s);
	volatile int* x = (volatile int*) __cosmix_suvm_annotation(malloc(s));
	
	for (int i=0;i<s/sizeof(int);i++) {
		x[i] = i;
	}

	g_test1 =  &x[1];
	g_test2 = &x[2];

	volatile int y1 = *g_test1;
	volatile int y2 = *g_test2;
	
	printf("y1=%d y2=%d\n", y1,y2);

	g_test2 = &y1;

	printf("g_test2=%d\n", *g_test2);

	g_test2 = g_test1;

	printf("g_test2=%d\n", *g_test2);
	
	volatile int** y = &x;

	printf("y=%d\n", **y);

	//free((void*)x);

	return 0;
}
