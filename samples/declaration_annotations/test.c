#include <stdio.h>

int main()
{
	volatile int x __attribute__((annotate("suvm")));
	x = 1;
	printf("%d\n", x);
	return 0;
}

