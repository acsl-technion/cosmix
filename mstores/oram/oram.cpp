#include <list>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <cassert>
#include <cstring>
#include "oram.h"
#include "oram_tests.h"
#include "array_tree.h"
#include "../../include/common.h"
#include "../common/slab_allocator.h"
#include <cmath>

#ifdef ORAM_UNTRUSTED
extern "C" void* __attribute__((optnone)) __cosmix_suvm_annotation(void* val)
{
    return val;
}
#elif ORAM_STORAGE

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

extern "C" void* __cosmix_storage_annotation(void* val);
#endif

#ifdef SDK_BUILD
#include <sgx_trts.h>
#include <sgx_error.h>
#include <sgx_tcrypto.h>
#else
#include <iostream>
#endif

#ifndef SDK_BUILD


using std::cout;
using std::endl;

typedef int sgx_status_t;
#define SGX_SUCCESS (0)

#define LINEAR_SCAN 1

sgx_status_t sgx_read_rand(unsigned char* val, size_t length_in_bytes)
{
    // not efficient since we read one random byte and discard the rest for each call to rand()
    for (unsigned int i = 0; i < length_in_bytes; ++i) {
        val[i] = rand() & 0xFF;
    }

	return SGX_SUCCESS;
}

#ifdef ORAM_DBG_PRINT
#define TRACE(...) printf(__VA_ARGS__)
#else
#define TRACE(...)
#endif
#define OASSERT(cond) assert(cond)
#else
#ifdef ORAM_DBG_PRINT
#define TRACE(...) g_debug(__VA_ARGS__)
#define OASSERT(cond) ASSERT(cond)
#else
#define TRACE(...)
#define OASSERT(cond) ASSERT(cond)
#endif
#endif

typedef unsigned int uint;

#define BLOCK_INIT_VAL (0xFF)
#define IS_DUMMY(block) ((block).id == BLOCK_DUMMY)
#define IS_NOT_DUMMY(block) ((block).id != BLOCK_DUMMY)

// Dummy block - used in ORAM whenever no actual data is stored
static block_t dummy_block;
static ORAM_ctx_t* g_oram;
static bucket_t* g_oram_tree;

static uintptr_t g_base_oram_addr = 0;
static SlabAllocator g_oram_allocator;

ORAM_ctx_t* GetORAM()
{
    return g_oram;
}

bucket_t* GetORAMTree()
{
    return g_oram_tree;
}

STATIC inline void set_dummy(block_t& block, bool is_dummy)
{
    block.id = is_dummy ? block.id : BLOCK_DUMMY;
}

STATIC void print_block(const block_t& block)
{
    for (uint i = 0; i < sizeof(block.data); ++i) {
        TRACE("%02X ", block.data[i]);
    }
    TRACE("\n");
}

STATIC unsigned int get_rand_pos(unsigned int num_leaves)
{
    unsigned int new_pos;
    sgx_status_t status  = sgx_read_rand(reinterpret_cast<unsigned char*>(&new_pos), sizeof(new_pos));
    OASSERT(SGX_SUCCESS == status);
    return  new_pos % num_leaves; // truncate to 0..L-1
}

void MAYALIAS(void* p, void* q){
  printf("\n");
}


/**
 * Recursive initialization of the ORAM tree
 * @param node Pointer to the current node to be created
 * @param parent Pointer to parent node
 * @param level Current depth
 * @return
 */

STATIC void init_tree(const unsigned int tree_height)
{
    auto num_buckets = get_nodes_num(tree_height);
    size_t size = num_buckets * sizeof(bucket_t);
    bucket_t* buckets = nullptr;

#ifdef ORAM_UNTRUSTED
    buckets = (bucket_t*) __cosmix_suvm_annotation(malloc(size));
#elif ORAM_STORAGE
    int fd = open("oram_storage.bin", O_RDWR | O_CREAT | O_TRUNC, (mode_t) 0600);
    if (fd < 0)
    {
        g_debug("ERROR allocate storage for ORAM\n");
        abort();
    }

    lseek(fd, size-1, SEEK_SET);
    write(fd, "", 1);

    void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    buckets = (bucket_t*) __cosmix_storage_annotation(ptr);
    close(fd);
#else // regular EPC memory
    buckets = (bucket_t*) malloc(size);
#endif

    OASSERT(buckets);

    for (unsigned int j = 0; j < num_buckets; ++j) {
        // init bucket with (later on encrypted) dummy blocks
        for (unsigned int i = 0; i < BUCKET_SIZE; ++i) {
            memset(buckets[j].blocks[i].data, BLOCK_INIT_VAL, BLOCK_SIZE);
	    
            //set_dummy((*head)[j].blocks[i], true);
            buckets[j].blocks[i].id = BLOCK_DUMMY;
        }
    }

    // set head to allocated buckets
    // 
    g_oram_tree = buckets;
}

STATIC void cleanup_tree()
{
    free(g_oram_tree);
}

int ORAM_mstore_init(void* priv_data)
{
	// Guard against double initializations - assume thread safety here
    //
    if (nullptr != g_oram) 
	{		
		return ORAM_EEXIST;
	}

    g_base_oram_addr = 0xdeadbeef000;
	g_oram_allocator.init_slab((void*)g_base_oram_addr, ORAM_SIZE, BLOCK_SIZE);
	uint32_t height = ceil(log2(NUM_OF_BLOCKS))-1;

    if (priv_data)
    {
        height = *(uint32_t*)priv_data;
    }

    g_oram = new (std::nothrow) ORAM_ctx_t();
    if (nullptr == g_oram) 
    {
        return ORAM_EMALLOC;
    }

    g_oram->height = height;

    // init dummy block
    set_dummy(dummy_block, true);
    dummy_block.id = BLOCK_DUMMY;
    memset(dummy_block.data, BLOCK_INIT_VAL, sizeof(dummy_block.data));

    // server buckets are initialized to random encryptions of the dummy block
    init_tree(height);

    // init position map - set to random positions. We don't really need to set blocks to NULL as suggested
    // in the Path-ORAM paper, since we are not assuming newly allocated addresses are initialized
    // number of nodes in a binary tree of depth k is 2^(k+1) - 1
    const unsigned int num_nodes = get_nodes_num(g_oram->height);
    const unsigned int num_leaves = get_leaves_num(g_oram->height);
    const unsigned int num_blocks = get_blocks_num(num_nodes);

    TRACE("Initializing ORAM of height %d, with %d nodes and %d leaves\n", g_oram->height, num_nodes, num_leaves);

    g_oram->position_map = (unsigned int*)malloc(sizeof(unsigned int) * num_blocks);
    if (NULL == g_oram->position_map) 
    {
	    cleanup_tree();
	    delete g_oram;
	    return ORAM_EMALLOC;
    }

    for (unsigned int i = 0; i < num_blocks; ++i) 
    {
        g_oram->position_map[i] = get_rand_pos(num_leaves);
    }    

    return ORAM_OK;
}

ORAM_error_t ORAM_mstore_cleanup()
{
    if (nullptr == g_oram)
    {
        return ORAM_ENOTINIT;
        g_oram = nullptr;
    }

    g_oram->stash.clear();

    cleanup_tree();
    g_oram_tree = nullptr;

  	free(g_oram->position_map);
  	g_oram->position_map = nullptr;

    delete g_oram;
    g_oram = nullptr;

    return ORAM_OK;
}

/**
 * Read block from a bucket, while touching all of them
 * @param bucket
 * @return ORAM_OK on success, else error code
 */
STATIC std::list<block_t> read_bucket(bucket_t& bucket)
{
    std::list<block_t> blocks;
    block_t block;

    // TRACE("Reading bucket at addr %p...\n", &bucket);
    for (uint i = 0; i < BUCKET_SIZE; ++i) {
        // TODO: when we add encryption - decrypt block
		block = bucket.blocks[i];
        if (IS_NOT_DUMMY(block)) {
            TRACE("Read block %d at addr %p: ", bucket.blocks[i].id, &bucket.blocks[i]);
            blocks.push_back(block);
        }
		set_dummy(bucket.blocks[i], true); // mark as dummy after fetching block to stash
    }

    return blocks;
}

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


STATIC ORAM_error_t __attribute__((optnone)) write_stash_to_oram(ORAM_ctx_t* oram, uint leaf_num)
{
    const uint num_leaves = get_leaves_num(oram->height);
    const uint num_buckets = get_nodes_num(oram->height);
    const uint num_blocks = get_blocks_num(num_buckets);

    TRACE("Stash size: %lu\n", oram->stash.size());

    // Write path back to ORAM.
    // Include additional blocks from the stash if they can be placed.
    // Buckets are greedily filled with blocks from the stash, going back
    // from leafs to root and ensuring blocks are pushed as deep into
    // the tree as possible.
    std::unordered_map<unsigned int, std::vector<std::list<block_ptr_t>::iterator>>
      level_to_stash_iter_to_write_map;
    unsigned int total_to_write = num_blocks;

    for (auto stash_iter = oram->stash.begin(); stash_iter != oram->stash.end(); stash_iter++) {
        OASSERT(stash_iter->block->id < num_blocks);

        if (total_to_write == 0) {
            break;
        }

        // if the position of stash_iter id is in the current path  - done
        // OASSERT(stash_iter->block->pos == oram->position_map[stash_iter->block->id]);
        unsigned int curr_pos = stash_iter->block->pos;
        OASSERT(curr_pos < num_leaves);

        unsigned int curr_index = num_buckets -1 - num_leaves + leaf_num;
        curr_pos = num_buckets -1 - num_leaves + curr_pos;

        for (unsigned int level = oram->height; level > 0; level--) {
            OASSERT(level_to_stash_iter_to_write_map[level].size() <= BUCKET_SIZE);

            if (level_to_stash_iter_to_write_map[level].size() == BUCKET_SIZE) {
                curr_index = parent(curr_index);
                curr_pos = parent(curr_pos);
                continue;
            }

            if (curr_index == curr_pos) {                
                level_to_stash_iter_to_write_map[level].push_back(stash_iter);
                total_to_write--;
                break;
            }

            curr_index = parent(curr_index);
            curr_pos = parent(curr_pos);
        }
    }

    unsigned int index = num_buckets -1 - num_leaves + leaf_num;

    for (unsigned int level = oram->height; level > 0; level--) {
        for (unsigned int i = 0; i < BUCKET_SIZE; i++) {
            // Perform write to ORAM tree from the stash
            if (i < level_to_stash_iter_to_write_map[level].size()) {
                //oram->head[index].blocks[i] = *(level_to_stash_iter_to_write_map[level][i]->block);
                // MAYALIAS(g_oram_tree, &g_oram_tree[index].blocks[i]);
		memcpy(&g_oram_tree[index].blocks[i], level_to_stash_iter_to_write_map[level][i]->block, sizeof(block_t));
                oram->stash.erase(level_to_stash_iter_to_write_map[level][i]);
            }
            else {
                // Pad write dummy block
                //oram->head[index].blocks[i] = dummy_block;
		memcpy(&g_oram_tree[index].blocks[i], &dummy_block, sizeof(block_t));
            }
        }

        index = parent(index);
    }

    TRACE("Stash_size after writing back to ORAM tree: %lu\n", oram->stash.size());
    return ORAM_OK;
}

bool is_in_stash(ORAM_ctx* const oram, block_id_t block_id)
{
    for (auto stash_iter = oram->stash.begin(); stash_iter != oram->stash.end(); stash_iter++) 
    {
        if (stash_iter->block->id == block_id)
        {
            return true;
        }
    }

    return false;
}

/**
 * Access data stored in ORAM, for read/write operations
 * @param block_id
 * @param old_block always NULL, used to fetch block content's obliviously
 * @param new_block New block content
 * @param is_write
 * @return
 */
STATIC ORAM_error_t __attribute__((optnone)) oram_access(block_id_t block_id,
								block_t* old_block,
                                const size_t offset, byte* data, size_t len, bool is_write)
{
    block_t* old_blk_ptr = NULL;
    bool found_in_stash = false;
    block_t local_block;
    unsigned int leaf_num;

    OASSERT(NULL != g_oram);

    if (offset + len > BLOCK_SIZE) {
        TRACE("offset + size is out of range\n");
        return ORAM_ERANGE;
    }

    memset(local_block.data, BLOCK_INIT_VAL, sizeof(local_block.data));

    if (NULL == old_block) {
        old_block = &local_block;
    }

    const unsigned int num_leaves = get_leaves_num(g_oram->height);
    const unsigned int num_buckets = get_nodes_num(g_oram->height);
    const unsigned int num_blocks = num_buckets * BUCKET_SIZE;

    // Remap the position of block "block" to a new random one, after saving the old position.
    uint new_pos = get_rand_pos(num_leaves);

#if LINEAR_SCAN
    unsigned long pos_to_write = (unsigned long)BLOCK_NULL;
    const int shift = sizeof(unsigned int)*8; // 8 bits in a byte
    unsigned long id_to_check = block_id % 2 == 0 ? block_id : block_id - 1;
    unsigned long res = leaf_num;
    unsigned long new_pos_long = (unsigned long)new_pos;
    if (block_id % 2 == 1)
    {
        new_pos_long = new_pos_long << shift;
    }

    for (uint i = 0; i < num_blocks; i+=2) {
        unsigned long* mem_ptr = (unsigned long*)&g_oram->position_map[i];
        unsigned long true_val = *mem_ptr;
        res = cmov(id_to_check == i, true_val, res);
        pos_to_write = cmov(id_to_check == i, new_pos_long, true_val);
        unsigned int pos_to_write_0 = (unsigned int)pos_to_write;
        unsigned int pos_to_write_1 = pos_to_write >> shift;
        unsigned int mem0 = (unsigned int)true_val;
        unsigned int mem1 = true_val >> shift;

        if (block_id % 2 == 0)
        {
            unsigned long temp = (unsigned long)mem1;
            temp = temp << shift;
            temp = temp | pos_to_write_0;
            pos_to_write = temp;
        } 
        else    
        {
            unsigned long temp = (unsigned long)pos_to_write_1;
            temp = temp << shift;
            temp = temp | mem0;
            pos_to_write = temp;
        }
        *mem_ptr = pos_to_write;
    }

    leaf_num = block_id % 2 == 0 ? (unsigned int)res : res >> shift;
#else
	leaf_num = oram->position_map[block_id];
    oram->position_map[block_id] = new_pos;
#endif

    TRACE("Leaf num: %u\n", leaf_num);

    TRACE("Accessing block %d  mapped to leaf %d\n", block_id, leaf_num);
    OASSERT(leaf_num < num_leaves);

    if (block_id >= num_blocks) {
        return ORAM_EBLCKID;
    }

    // first search for block in stash
    for (auto stash_iter = g_oram->stash.begin(); stash_iter != g_oram->stash.end(); ++stash_iter) {
        OASSERT( IS_NOT_DUMMY(*(stash_iter->block)) );
        if (stash_iter->block->id == block_id) {
            TRACE("Block %d found in stash\n", block_id);
            stash_iter->block->pos = new_pos;
            *old_block = *(stash_iter->block);
            old_blk_ptr = stash_iter->block;
            found_in_stash = true;
            // We could break here, but we need to go over the whole stash regardless to prevent a timing side-channel
			//break; // block found in stash
        }
    }

    if (not found_in_stash) {
        TRACE("Block %d NOT FOUND in stash\n", block_id);
    }

    // Read the path containing block "block", and store the blocks in the stash
    TRACE("Traversing path of leaf %d\n", leaf_num);

    unsigned int index = num_buckets -1 - num_leaves + leaf_num;
    do {
        // this is currently wasteful since read_bucket reads the blocks once to a temporary list, and
        // then we copy them from the list to the stash
        //auto blocks = read_bucket(oram->head[index]);

	for (uint x=0;x<BUCKET_SIZE;x++) {
        //for (auto block_iter = blocks.begin(); block_iter != blocks.end(); ++block_iter) {
            // MAYALIAS(g_oram_tree, &g_oram_tree[index].blocks[x].id);
            // MAYALIAS(g_oram_tree, &g_oram_tree[index].blocks[x]);
	    uint id = g_oram_tree[index].blocks[x].id;
            if ((id != BLOCK_DUMMY) && not is_in_stash(g_oram, id)) {
                TRACE("Read block %d into stash\n", block_iter->id);
                block_t* tmp_block_ptr = (block_t*) malloc(sizeof(block_t));
		        memcpy(tmp_block_ptr, &g_oram_tree[index].blocks[x], sizeof(block_t));
                //*tmp_block_ptr = *block_iter;
                auto stash_iter = g_oram->stash.insert(g_oram->stash.end(), block_ptr_t(tmp_block_ptr));

                if (tmp_block_ptr->id == block_id) {
                    stash_iter->block->pos = new_pos;
                    old_blk_ptr = (stash_iter->block); // save pointer to block
                    *old_block = *(stash_iter->block);   // store old block data
                    found_in_stash = true;
                }
            }
        }

        index = parent(index);
    } while (index > 0);

    TRACE("Stash size after reading from ORAM tree: %lu\n", g_oram->stash.size());

    if (is_write) {
        // Update block: replace old data in stash with new one.
        TRACE("Block %d was remapped to leaf %d\n", block_id, g_oram->position_map[block_id]);

        block_t* new_block = (block_t*) malloc(sizeof(block_t));
        // memset(new_block->data, BLOCK_INIT_VAL, sizeof(new_block->data));

        if (NULL != old_blk_ptr) {
            TRACE("Overwriting old block\n");
            *new_block = *old_block;
        }
        else {
            OASSERT(not found_in_stash);
            TRACE("Creating a new block %d\n", block_id);
            set_dummy(*new_block, false);
            new_block->id = block_id;
            new_block->pos = new_pos;
        }

        memcpy(new_block->data + offset, data, len);
        TRACE("New block content: ");

        if (not found_in_stash) {
            // in case block id was not there already
            TRACE("Pushing block into stash\n");
            g_oram->stash.push_back(block_ptr_t(new_block));
        }
        else {
            TRACE("Updating existing block in stash\n");
            // block id was found
            OASSERT(NULL != old_blk_ptr);
            *old_blk_ptr = *new_block;
            free(new_block);
        }
    }
    else
    {
        // old_block is already oblivious, so we can use memcpy to return the actual data to the user's buffer
        //
        memcpy(data, old_block->data + offset, len);        
    }
    

    return write_stash_to_oram(g_oram, leaf_num);
}

ORAM_error_t ORAM_read(block_id_t block_id,
					             block_t* const old_block)
{
    auto err = oram_access(block_id, old_block, 0, NULL, 0, false);
    return err;
}

ORAM_error_t ORAM_write(block_id_t block_id,
						            block_t* const old_block,
                        const size_t offset, byte* data, size_t len)
{
    return oram_access(block_id, old_block, offset, data, len, true);
}


void ORAM_mpf_handler_d(void* ptr, void* dst, size_t s)
{
    size_t offset = (uintptr_t)ptr - g_base_oram_addr;
	uint32_t block_id = offset / BLOCK_SIZE;
	ASSERT(block_id <= NUM_OF_BLOCKS);	
	uint32_t block_offset = offset & (BLOCK_SIZE -1);
    byte* dest = (byte*)dst;

    // Read in chunks of blocks
    //
    size_t remain = s;
    while (remain > 0)
    {
        // read from offset, untill BLOCK end
        size_t to_read = std::min(BLOCK_SIZE - (size_t)block_offset, remain);
    	ORAM_error_t error = oram_access(block_id, nullptr, block_offset, dest, to_read, false);
    	ASSERT(ORAM_OK == error);

        dest += to_read;
        block_offset = 0;
        block_id++;
        remain -= to_read;
    }

    // Note to self:
    // 1. Every mstore should have page size, that's when the handler is invoked.
    // 2. Direct mstores do not have a page cache, their offset is from base that is the start of the "PAGE"
    // 3. For optimization purpose, every direct mstore will have thread local BLOCK used for mpf_handler and write_backs
    // 4. This is internal optimization, so not part of the runtime.
    // 5. dest is stack allocated, passed from compiler to the runtime to the mstore, so should memcpy to it eventually in the mstore
}

void ORAM_write_back(void* ptr, void* dst, size_t s)
{
    size_t offset = (uintptr_t)ptr - g_base_oram_addr;
	uint32_t block_id = offset / BLOCK_SIZE;
	ASSERT(block_id <= NUM_OF_BLOCKS);	
	uint32_t block_offset = offset & (BLOCK_SIZE -1);
    byte* dest = (byte*)dst;

    // Write in chunks of blocks
    //
    size_t remain = s;
    while (remain > 0)
    {
        // read from offset, untill BLOCK end
        size_t to_write = std::min(BLOCK_SIZE - (size_t)block_offset, remain);
    	ORAM_error_t error = oram_access(block_id, nullptr, block_offset, dest, to_write, true);
    	ASSERT(ORAM_OK == error);

        dest += to_write;
        block_offset = 0;
        block_id++;
        remain -= to_write;
    }
}

void* ORAM_mstore_alloc(size_t size, void* private_data)
{
    return g_oram_allocator.alloc(size);
}

void ORAM_mstore_free(void* ptr)
{
    return g_oram_allocator.free_alloc(ptr);
}

size_t ORAM_mstore_alloc_size(void* ptr)
{
    return g_oram_allocator.alloc_size(ptr);
}

size_t ORAM_mstore_get_mpage_size()
{
    return BLOCK_SIZE;
}
