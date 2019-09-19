#include "page_cache.h"
#include "SyncUtils.h"
#include "mstore_common.h"

// Note: not thread safe, responsibility of the caller
//
void init_page_cache(struct page_cache* pc, uintptr_t* base_page_cache_ptr, size_t page_cache_size, size_t page_size)
{
    // We allocate an extra page for HW pages alignment, giving better performance in some cases
    //
	*base_page_cache_ptr = (uintptr_t) _real_malloc(page_cache_size+0x1000l);
	*base_page_cache_ptr += 0x1000l;
    // Validate allocation succeeded
    //
    ASSERT (*base_page_cache_ptr != 0); 

    // Note: without saving original pointer it is impossible to clean later, but page cache is expected to be enabled throughout the enclave lifetime as is.
    //
	*base_page_cache_ptr &= ~0xFFF; 

	for (size_t i=0;i<page_cache_size/page_size;i++)
	{
		unsigned char* page = (unsigned char*)(*base_page_cache_ptr + i * page_size);
		pc->g_free_epc_pages.push_back(page);
	}

    pc->m_num_of_free_pages = page_cache_size/page_size;
}

void cleanup_page_cache(struct page_cache* pc)
{
    // TODO: free the pages allocated
}

unsigned char* pop_free_page(struct page_cache* pc)
{
    unsigned char* res = nullptr;
    spin_lock(&pc->g_free_epc_pages_lock);

    if (pc->m_num_of_free_pages > 0)
    {
        auto free_epc_page_it = pc->g_free_epc_pages.begin();
        ASSERT (free_epc_page_it != pc->g_free_epc_pages.end());
        res = pc->g_free_epc_pages.back();
        pc->g_free_epc_pages.pop_back();
        pc->m_num_of_free_pages--;
    }

    spin_unlock(&pc->g_free_epc_pages_lock);

    return res;
}

void push_free_page(struct page_cache* pc, unsigned char* page)
{
    spin_lock(&pc->g_free_epc_pages_lock);
    
    pc->g_free_epc_pages.push_back(page);
    pc->m_num_of_free_pages++;

    spin_unlock(&pc->g_free_epc_pages_lock);
}
