#include <cassert>
#include "oram_tests.h"

const unsigned int NUM_ITER = 100;

void profile_writes(ORAM_ctx_t* oram)
{
	unsigned int num_blocks = get_blocks_num(get_nodes_num(oram->height));
	block_t old_block;
	unsigned char data[BLOCK_SIZE] = "";

	for (unsigned int i = 0; i < num_blocks; ++i) {
		ORAM_error_t error = ORAM_write(oram, i, &old_block, 0, data, sizeof(data));
		assert(ORAM_OK == error);
	}
}

void profile_reads(ORAM_ctx_t* oram)
{
	unsigned int num_blocks = get_blocks_num(get_nodes_num(oram->height));
	block_t block;
	
	for (unsigned int i = 0; i < num_blocks; ++i) {
		ORAM_error_t error = ORAM_read(oram, i, &block);
		assert(ORAM_OK == error);
	}
}

int main()
{
	ORAM_error_t error;
	ORAM_ctx_t* oram = ORAM_init(10, &error);
	assert(NULL != oram);

	// profile_writes(oram);
	for (unsigned int i = 0; i < NUM_ITER; ++i) {
		profile_reads(oram);
	}

	ORAM_cleanup(oram);
	return 0;
}
