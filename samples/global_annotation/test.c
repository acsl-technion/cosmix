#include <stdio.h>

volatile int x __attribute__((annotate("suvm")));

int main()
{
	x = 1;
	printf("%d\n",x);
	return 0;
}

