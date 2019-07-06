#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <string.h>	
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define TRUE 1
#define FALSE 0

extern void* __cosmix_oram_annotation(void* ptr);
extern void* __cosmix_suvm_annotation(void* ptr);
extern void* __cosmix_storage_annotation(void* ptr);

int main(int argc, char** argv) 
{
	if (argc < 2)
	{
		printf("Usage: ./app [BUFFER_SIZE_IN_MB] [Optional num of ops]\n");
		exit(-1);
	}
	
	int res = 0;
	srand(time(0));
	struct timespec start, stop;
	size_t s = atoi(argv[1])*1024*1024;
	size_t size_aligned = s + 0x1000l;
	size_t block_size = 0x1000;
	size_t num_ops = 1000000;
	if (argc == 3)
	{
		num_ops = atoi(argv[2]);
	}
	
	char read_test = TRUE;
	char write_test = FALSE;
	char temp[block_size];
	
	for (int i=0;i<block_size;i++) {
		temp[i]=i;
	}	

#ifdef ORAM_TEST
	unsigned char* x = (unsigned char*)__cosmix_oram_annotation(malloc(size_aligned));
#elif SUVM_TEST
	unsigned char* x = (unsigned char*)__cosmix_suvm_annotation(malloc(size_aligned));
#elif STORAGE_TEST
	int fd = open("test_storage.bin", O_RDWR | O_CREAT | O_TRUNC, (mode_t) 0600);
	if (fd < 0)
	{
		printf("ERROR open file for storage test\n");
		exit(-1);
	}

	lseek(fd, size_aligned-1, SEEK_SET);
	write(fd, "", 1);

	void* ptr = mmap(0, size_aligned, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	unsigned char* x = (unsigned char*)__cosmix_storage_annotation(ptr);
	close(fd);
#else // native test
	unsigned char* x = (unsigned char*)malloc(size_aligned);
#endif
	assert(x);

	unsigned char* y = x + 0x1000;
	y = (unsigned char*)((uintptr_t)y & ~0xFFF);

	// Warmup
	// 
	memset(y, 0, s);

	// Real test begin, start clock	
	//
	assert (clock_gettime(CLOCK_REALTIME, &start) != -1);
 
	for (unsigned int i=0;i<num_ops;i++) {
		unsigned int j = rand() % s;
		//j -= block_size;
		j &= ~(block_size - 1);
		unsigned char* curr = &y[j];
		for (int k=0;k<block_size;k++)
		{		
			// write
			*curr = ((k+j) % 255);
			curr++;
		}
	}


	for (unsigned int i=0;i<num_ops;i++) {
		unsigned int j = rand() % s;
		//j -= block_size;
		j &= ~(block_size - 1);
		unsigned char* curr = &y[j];

		// Read-only test		
		for (int k=0;k<block_size;k++)
		{
			*temp += *curr;
			if (*curr != ((k+j) % 255) && *curr != 0)
			{
				printf("Failed: expected=%d, got=%d, curr=%p base=%p\n", k, *curr, curr, y);
				exit(-1);
			}
			curr++;
		}
	}

	// Test done, print out the time it took, and overall throughput achieved.
	//
	assert (clock_gettime(CLOCK_REALTIME, &stop) != -1);
	double total_latency = ( stop.tv_sec - start.tv_sec ) + ( stop.tv_nsec - start.tv_nsec ) / 1e9;
	double avg_latency_per_access = total_latency / num_ops;
	double avg_tp = num_ops / total_latency;
	printf("Ops: %lu, Latency: %lf, Throughput: %lf\n", num_ops, avg_latency_per_access, avg_tp);

	// Make sure code isn't optimized out through DCE, or other aggressive optimizations
	//
	res = temp[0];

	// Done
	//
#ifndef STORAGE_TEST
	free(x);
#else
	munmap(ptr, size_aligned);
#endif
	
	return res;
}
