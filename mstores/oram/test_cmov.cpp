#include <stdio.h>

static inline unsigned long cmov(int pred, unsigned long t_val, unsigned long f_val) {
    unsigned long result;
    __asm__  (
        "mov %2, %0\n\t"
        "test %1, %1\n\t"
        "cmovz %3, %0\n\t"
    : [output] "=&r" (result) // & means early clobber. Was missing in Raccoon
    : [input] "r" (pred), "r" (t_val), "r" (f_val)
    : "cc"
    );
    return result;
}

int main()
{
	unsigned long result = 0;
	result = cmov(1, 2, 3);
	printf("Result: %lu\n", result);
	result = cmov(0, 2, 3);
	printf("Result: %lu\n", result);
}
