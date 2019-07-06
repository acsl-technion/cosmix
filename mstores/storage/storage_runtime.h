#ifndef _STORAGE_RUNTIME_H
#define _STORAGE_RUNTIME_H

#include "../../include/common.h"
//#include "page_cache.h"
#include <unistd.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STORAGE_BS_BITS 31
#define STORAGE_BS_SIZE (1L << STORAGE_BS_BITS) // 2GB
// #define STORAGE_BS_MASK (STORAGE_BS_BITS-1L)

#ifndef STORAGE_PAGE_CACHE_BITS
#define STORAGE_PAGE_CACHE_BITS 26
#endif

#ifndef STORAGE_PAGE_BITS
#define STORAGE_PAGE_BITS 12
#endif

#define STORAGE_PAGE_SIZE (1 << STORAGE_PAGE_BITS)
#define STORAGE_PAGE_OFFSET_MASK (STORAGE_PAGE_SIZE-1)

// Hard coded value of files tracked with this mstore
#ifndef STORAGE_MMAP_FILE_PATH
#define STORAGE_MMAP_FILE_PATH "test.dat"
#endif

#ifndef MAX_FILE_SIZE
#define MAX_FILE_SIZE (1L << 34) // 16 GiB (ext4)
#endif

#define STORAGE_PAGE_CACHE_SIZE (1 << STORAGE_PAGE_CACHE_BITS) // 64 MB
#define STORAGE_PAGE_CACHE_NUM_OF_ENTRIES (STORAGE_PAGE_CACHE_SIZE / STORAGE_PAGE_SIZE)

// const unsigned int STORAGE_TLB_SIZE = 5;

// extern uintptr_t g_base_storage_bs_ptr;
// extern uintptr_t g_storage_base_page_cache_ptr;
// struct page_cache g_storage_page_cache;
// extern __thread struct s_victim_cache gt_STORAGE_TLB[STORAGE_TLB_SIZE];

// void* page_fault_storage(void* ptr, char dirty);
// int storage_init();
// int storage_cleanup();

// File I/O API
void storage_mstore_open(char* filename, int fd, char always_register_fd, char* registered_fd);
void storage_mstore_close(int fd);
// uintptr_t storage_get_base_ptr_for_fd(int fd);
// void storage_munmap(void* ptr);
// void storage_mmap(void* ptr);
// void storage_mremap(void* old, size_t new_len, int flags);
ssize_t storage_mstore_write(int fd, void* buf, size_t count);
ssize_t storage_mstore_read(int fd, void* buf, size_t count);

// Callback API
void* storage_mstore_alloc(size_t size, void* private_data);
size_t storage_mstore_alloc_size(void* ptr);
void storage_mstore_free(void* ptr);

// Should get all private parameters via a struct based on parsed values from the json configuration file
//
int storage_mstore_init(void* priv_data);

int storage_mstore_cleanup();
void* storage_mpf_handler_c(void* bs_page);
void storage_flush(void* ptr, size_t size);
void storage_notify_tlb_cached(void* ptr);
void storage_notify_tlb_dropped(void* ptr, bool dirty);

// Encapsulate mstorage, mpage_cache, and mpage_size
uintptr_t storage_mstore_get_mpage_cache_base_ptr();
uintptr_t storage_mstore_get_mstorage_page(uintptr_t ptr);
size_t storage_mstore_get_mpage_size();
int storage_mstore_get_mpage_bits();

// mprotect -> only with SGX2 capabilities.

#ifdef __cplusplus
}
#endif

#endif
