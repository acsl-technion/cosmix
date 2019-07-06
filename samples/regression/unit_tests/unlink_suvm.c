#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
	size_t s = 1024*1024; // just more than 256MB
	volatile int* x = (volatile int*) malloc(s);
	
	for (int i=0;i<s/sizeof(int);i++) {
        volatile int* temp = &x[100];
        for (int j=0;j<i;j+=1024) {
		    x[j] = i;

            if (i==0 && j==0) {
                printf("here\n");
                temp = &x[200];
            }
        }
        
        *temp = 47;
	}

    free((void*)x);

	return 0;
}
