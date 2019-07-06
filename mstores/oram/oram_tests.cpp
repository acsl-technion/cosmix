#include <cstdlib>
#include <cassert>
#include <iostream>
#include <string.h>
#include "oram_tests.h"
#include "array_tree.h"
#include "../../include/common.h"

const unsigned int STASH_SIZE_THRESHOLD = 1000;

using std::cout;
using std::endl;

DBG_FUNC g_debug;

// void oram_test_debug(const char *fmt, ...)
// {
// 	char buf[BUFSIZ] = {'\0'};
// 	va_list ap;
// 	va_start(ap, fmt);
// 	vsnprintf(buf, BUFSIZ, fmt, ap);
// 	va_end(ap);
// 	fprintf(stderr,"%s", buf);
// }

static void print_tree(bucket_t* head, unsigned int size) {
    assert(NULL != head);

    for (unsigned int bucket = 0; bucket < size; ++bucket) {
        cout << "[";
        for (unsigned int i = 0; i < BUCKET_SIZE; ++i) {
            cout << head[bucket].blocks[i].id << ".";
        }
        cout << "]" << endl;
    }
}

static void print_stash(const std::list<block_ptr_t>& stash)
{
    cout << "(";
    for (auto iter = stash.begin(); iter != stash.end(); ++iter) {
        cout << iter->block->id << ".";
    }
    cout << ")" << endl;
}

static void test_init_tree()
{
	init_tree(1);
	cleanup_tree();
}

static void test_oram_init()
{
    uint32_t height = DEFAULT_TREE_HEIGHT;
	int error = ORAM_mstore_init(&height);
	assert(ORAM_OK == error);
    assert(nullptr != GetORAM());
	ORAM_mstore_cleanup();
}

static void test_oram_access()
{
    uint32_t height = 1;
	int error = ORAM_mstore_init(&height);
	assert(ORAM_OK == error);
    assert(nullptr != GetORAM());

    print_tree(GetORAMTree(), get_nodes_num(GetORAM()->height));

    block_t old_block;
	error = ORAM_read(0, &old_block);
    assert(ORAM_OK == error);

    print_tree(GetORAMTree(), get_nodes_num(GetORAM()->height));
    print_stash(GetORAM()->stash);

    byte data[BLOCK_SIZE];
    memset(data, 0xF3, sizeof(data));

    error = ORAM_write(2, &old_block, 0, data, sizeof(data));
    assert(ORAM_OK == error);

    print_tree(GetORAMTree(), get_nodes_num(GetORAM()->height));
    print_stash(GetORAM()->stash);

    error = ORAM_read(2, &old_block);
    assert(ORAM_OK == error);

    assert(0 == memcmp(old_block.data, data, sizeof(data)));

    const unsigned int buckets_num = get_nodes_num(GetORAM()->height);
    print_tree(GetORAMTree(), buckets_num);
    print_stash(GetORAM()->stash);

    const unsigned int blocks_num = get_blocks_num(buckets_num);
    for (block_id_t i = 0; i < blocks_num; ++i) {
        error = ORAM_read(i, &old_block);
        assert(ORAM_OK == error);
    }

	ORAM_mstore_cleanup();
}

static void test_access_with_offset()
{
    uint32_t height = 10;
	int error = ORAM_mstore_init(&height);
	assert(ORAM_OK == error);
    assert(nullptr != GetORAM());

    byte data[BLOCK_SIZE / 2];
    memset(data, 0xC4, sizeof(data));

    error = ORAM_write(50, NULL, 5, data, sizeof(data));
    assert(ORAM_OK == error);

    byte data2[BLOCK_SIZE / 2];
    memset(data2, 0xA2, sizeof(data));
    error = ORAM_write(49, NULL, 5, data2, sizeof(data2));
    assert(ORAM_OK == error);

    block_t old_block;
    error = ORAM_read(50, &old_block);
    assert(ORAM_OK == error);

    // print_block(old_block);
    assert(0 == memcmp(old_block.data + 5, data, sizeof(data)));

    // another read to check consistency

    error = ORAM_read(49, &old_block);
    assert(ORAM_OK == error);

    // print_block(old_block);
    assert(0 == memcmp(old_block.data + 5, data2, sizeof(data2)));

    ORAM_mstore_cleanup();
}

static void test_access_with_offset_fail()
{
    uint32_t height = 10;
	int error = ORAM_mstore_init(&height);
	assert(ORAM_OK == error);
    assert(nullptr != GetORAM());

    byte data[BLOCK_SIZE / 2];
    for (uint32_t i = 0; i < sizeof(data); i++) {
        data[i] = i;
    }

    for (uint32_t i = 0; i < sizeof(data); i++) {
		block_t tmp;
		error = ORAM_read(0, &tmp);
		assert(ORAM_OK == error);

        // printf("Read block %d from ORAM: ", tmp.id);
		// print_block(tmp);

        error = ORAM_write(0, NULL, 5 + i, &data[i], 1);
        assert(ORAM_OK == error);
    }

    block_t old_block;
    error = ORAM_read(0, &old_block);
    assert(ORAM_OK == error);
    // print_block(old_block);

    assert(0 == memcmp(old_block.data + 5, data, sizeof(data)));

    ORAM_mstore_cleanup();
}

static void test_stash_size()
{
    unsigned int max_stash_size = 0;

    uint32_t height = 10;
	int error = ORAM_mstore_init(&height);
	assert(ORAM_OK == error);
    assert(nullptr != GetORAM());

    cout << "Testing that the whole stash is successfully written back after ORAM access..." << endl;

    byte data[BLOCK_SIZE] = {};
    block_t old_block;

    printf("\e[?25l");

    for (unsigned int i = 0; i < 50000; ++i) {

        error = ORAM_write(i % get_nodes_num(GetORAM()->height), &old_block, 0, data, sizeof(data));
        assert(ORAM_OK == error);
        assert(GetORAM()->stash.size() < STASH_SIZE_THRESHOLD);

        if (GetORAM()->stash.size() > max_stash_size) {
            max_stash_size = GetORAM()->stash.size();
        }

        error = ORAM_read(i % get_nodes_num(GetORAM()->height), &old_block);
        assert(ORAM_OK == error);
        assert(GetORAM()->stash.size() < STASH_SIZE_THRESHOLD);

        if (GetORAM()->stash.size() > max_stash_size) {
            max_stash_size = GetORAM()->stash.size();
        }

        printf("\rIn progress: %u%%", i / 500);
    }
    
    cout << endl << "Max. stash size reached: " << max_stash_size << endl;
}

int main()
{
	test_init_tree();
	test_oram_init();
	test_oram_access();
    test_access_with_offset();
    test_access_with_offset_fail();
    test_stash_size();
	cout << "PASSED" << endl;
	return 0;
}
