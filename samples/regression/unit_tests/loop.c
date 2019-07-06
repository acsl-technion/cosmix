#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

extern int main(int argc, char** argv) {
	size_t s = 512*1024*1024; // just more than 256MB
/*  
	if (argc > 1) {
		s = atoi(argv[1]) * 1024 * 1024;
	}
*/
	char* x = malloc(s);
	assert(x != NULL);

	char priv[4096];
	for (int i=0;i<4096;i++) {
		priv[i]=i;
	}

	for (unsigned int i=0;i<10000;i++) {
		unsigned int j = rand();
		j %= s - 4096;
		j &= ~0xFFF;
		char* p = &x[j];
		for (int x=0;x<1000;x++) {
			p[x]=1234-x;
		}
	}

	int res = x[0];
	free((int*)x);

	return res;
}
