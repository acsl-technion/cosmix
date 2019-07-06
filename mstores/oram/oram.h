/**
 * oram.h
 * Created: Jan 13, 2017
 * Author: Yan Michalevsky
*/

#ifndef __ORAM_H_
#define __ORAM_H_

#ifdef __cplusplus
#include <cstdlib>
#else
#include <stdlib.h>
#endif

/*
	A simple explanation of Path-ORAM can be found at:
	http://ecrypt-eu.blogspot.com/2016/03/path-oram.html
*/

/* 
   Larger BUCKET_SIZE results in lower ORAM-failure probablity (stash exhausting),
   however, it increases the performance penalty on ORAM access.
   BUCKET_SIZE=4 would result in a negligible failure probability, BUCKET_SIZE=3 results in a very smalle
   probability, but we can probably tolerate BUCKET_SIZE=2.
*/
#define BUCKET_SIZE         (3)                     /* number of blocks in bucket, Z in Path-ORAM paper */

/* The min. BLOCK_SIZE that makes sense in terms of performance, is the size of a cache line,
   significantly improving performance. */
#define BLOCK_SIZE          (4096)                  /* block size in bytes */

#ifndef ORAM_BITS
#define ORAM_BITS 27
#else
#warning "ORAM SIZE PRVOIDED BY USER"
#endif

#define ORAM_SIZE (1L << ORAM_BITS)
#define NUM_OF_BLOCKS ((ORAM_SIZE) / (BLOCK_SIZE))
#define NUM_OF_BUCKETS ((NUM_OF_BLOCKS) / (BUCKET_SIZE))

#define BLOCK_NULL          ((unsigned int)-1)
#define BLOCK_DUMMY         ((unsigned int)-2)
#define DEFAULT_TREE_HEIGHT (10)                    /* L in Path-ORAM paper */

/* Later on this will be used for integrity checking
#define HASH_LEN         (32) */

typedef unsigned char byte;
typedef unsigned int block_id_t;

/* We do not currently encrypt the ORAM storage since the tree structure is allocated
 * inside the enclave. When paged out, the data will be encrypted by SGX anyhow.
 * TODO: Add support for out-of-enclave ORAM storage. In this case we need to encrypt the blocks.
 */

/* Forward declarations for structures */
struct block;
struct bucket;
struct ORAM_ctx;

typedef struct block {
    block_id_t id;          // block ID
    // unsigned int is_dummy;          // indicates a dummy block
    unsigned int pos;
    byte data[BLOCK_SIZE];
} block_t;

typedef struct bucket bucket_t;
typedef struct ORAM_ctx ORAM_ctx_t;

/* Error codes */
typedef enum ORAM_error {
    ORAM_OK,
    ORAM_EMALLOC,
    ORAM_EBLCKID,
    ORAM_ERANGE,
    ORAM_ENOTINIT,
    ORAM_EEXIST
} ORAM_error_t;

#ifdef __cplusplus
extern "C" {
#endif

#define get_nodes_num(height) ((1 << (height + 1)) - 1)
#define get_leaves_num(height) (1 << height)
#define get_blocks_num(nodes_num) (nodes_num * BUCKET_SIZE)

/**
 * Initialize ORAM server storage and client state.
 * @param priv_data internal ORAM mstore information passed from the CosMIX compiler
 * @return ORAM_OK if initialized successfully. Error code otherwise.
 */
int ORAM_mstore_init(void* priv_data);

/**
 * Read data from ORAM backend
 * @param oram
 * @param block
 * @param buffer
 * @param len
 * @return
 */
ORAM_error_t ORAM_read(block_id_t id, block_t* old_block);

/**
 * Store data in ORAM backend
 * @param oram
 * @param block
 * @param data
 * @param len
 * @return
 */
ORAM_error_t ORAM_write(block_id_t id, block_t* old_block,
                        size_t offset, byte* data, size_t len);

/**
 * Destructor - cleanup ORAM server and client states
 * @return ORAM_OK if cleanup was successful.
 */
ORAM_error_t ORAM_mstore_cleanup();

ORAM_ctx_t* GetORAM();

bucket_t* GetORAMTree();

void ORAM_mpf_handler_d(void* ptr, void* dst, size_t s);

void ORAM_write_back(void* ptr, void* dst, size_t s);

void* ORAM_mstore_alloc(size_t size, void* private_data);

void ORAM_mstore_free(void* ptr);

size_t ORAM_mstore_alloc_size(void* ptr);

size_t ORAM_mstore_get_mpage_size();

#ifdef __cplusplus
}
#endif

#endif
