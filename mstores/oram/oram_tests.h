//
// Created by yan on 1/25/18.
//

#ifndef SUVM_ORAM_TESTS_H
#define SUVM_ORAM_TESTS_H

#include <vector>
#include <list>
#include "oram.h"

#ifdef ORAM_TESTS
#define STATIC
#else
#define STATIC static
#endif

/* buckets are stored in a continuous array, and are addressed by their position */
struct bucket {
    // TODO: use hash for integrity checking
    // byte hash[HASH_LEN]; // hash of stored blocks and hashes of children - for integrity
    // unsigned int index; // index of current bucket in array
    block_t blocks[BUCKET_SIZE];   // position of current bucket in the bucket array
};

class block_ptr_t {
public:
    block_ptr_t(block_t* _block) 
    : block(_block) 
    { }

    block_ptr_t(const block_ptr_t& other)
        : block(other.block)
    {
        other.block = NULL;
    }
    
    ~block_ptr_t() {
        if (block) {
            free(block);
            block = NULL;
        }
    }

    mutable block_t* block;
};

/**
 * The position_map maps between blocks and leaf-buckets in the ORAM tree, and is of size 2^TREE_HEIGHT.
 * The leaves array is used for random reassignment of blocks to leaf-buckets.
 */
struct ORAM_ctx {
    // TODO: add encryption key
    // sgx_aes_gcm_128bit_key_t enc_key; // Encryption key used to encrypt/decrypt data stored in ORAM
    // bucket_t* head; // ORAM tree root
    unsigned int height; // ORAM tree height
    // client state
    unsigned int* position_map; // client position map
    std::list<block_ptr_t> stash; // client block stash
};

STATIC void print_block(const block_t& block);

STATIC void init_tree(const unsigned int tree_height);

STATIC void cleanup_tree();

STATIC std::vector<unsigned int> get_path(unsigned int leaf_index);

STATIC ORAM_error_t oram_access(ORAM_ctx_t* const oram, block_id_t block_id, block_t* const old_block,
                                const block_t* const new_block, bool is_write);

#endif //SUVM_ORAM_TESTS_H
