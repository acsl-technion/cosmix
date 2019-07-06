#ifndef _SUVM_RUNTIME_H
#define _SUVM_RUNTIME_H

#include "../../include/common.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SUVM_PAGE_CACHE_BITS
#define SUVM_PAGE_CACHE_BITS 26
#endif

#define SUVM_PAGE_CACHE_SIZE (1 << SUVM_PAGE_CACHE_BITS) // 64 MB
//#define SUVM_PAGE_CACHE_SIZE (45*1024*1024)
#define EVICT_CACHE_THRESHOLD 50

#define SUVM_BS_BITS 31
#define SUVM_BS_SIZE (1L << SUVM_BS_BITS) // 2GB
// #define SUVM_BS_MASK (SUVM_BS_SIZE-1L)

#ifndef SUVM_PAGE_BITS
#define SUVM_PAGE_BITS 12
#endif

#define SUVM_PAGE_SIZE (1 << SUVM_PAGE_BITS)
#define SUVM_PAGE_OFFSET_MASK (SUVM_PAGE_SIZE - 1)

#define NONCE_BYTE_SIZE 12
#define MAC_BYTE_SIZE 16

// extern volatile char* volatile m_ref_count;

// Callback API
void* suvm_mstore_alloc(size_t size, void* private_data);
size_t suvm_mstore_alloc_size(void* ptr);
void suvm_mstore_free(void* ptr);

int suvm_mstore_init(void* priv_data);
int suvm_mstore_cleanup();
void* suvm_mpf_handler_c(void* bs_page);
void suvm_flush(void* ptr, size_t size);
void suvm_notify_tlb_cached(void* ptr);
void suvm_notify_tlb_dropped(void* ptr, bool dirty);

// Encapsulate mstorage, mpage_cache, and mpage_size
uintptr_t suvm_mstore_get_mpage_cache_base_ptr();
uintptr_t suvm_mstore_get_mstorage_page(uintptr_t ptr);
size_t suvm_mstore_get_mpage_size();
int suvm_mstore_get_mpage_bits();

// Debug API - internal use
void debug_ref_count();

#ifdef __cplusplus
}
#endif

#endif
