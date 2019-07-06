#pragma once

#include "../../include/common.h"
#include <vector>

struct page_cache {
    // list of free pages in the page cache (for enclave this is stored in EPC) 
    // that are currently not used, i.e., does not have a mapping to a mstorage page in the PageTable
    //
    std::vector<unsigned char*> g_free_epc_pages;
    volatile unsigned char g_free_epc_pages_lock;    
    int m_num_of_free_pages;
};

void init_page_cache(struct page_cache* pc, uintptr_t* base_page_cache_ptr, size_t page_cache_size, size_t page_size);
void cleanup_page_cache(struct page_cache* pc);

unsigned char* pop_free_page(struct page_cache* pc);
void push_free_page(struct page_cache* pc, unsigned char* page);
