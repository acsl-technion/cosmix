/*
 * Runtime for Secured mmap
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>      /* vsnprintf */
#include <vector>
#include <assert.h>
#include  <math.h>

#include "storage_runtime.h"
#include "../common/SyncUtils.h"
#include "../common/StoragePageTable.h"
#include "../common/page_cache.h"
#include "../common/mstore_common.h"
#include "../../include/common.h"

#ifndef SDK_BUILD
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#endif

// __thread struct s_victim_cache gt_STORAGE_TLB[STORAGE_TLB_SIZE];

// protection is set via mmap or mprotect
struct protection_data
{
	off_t offset;
	size_t size;
	int prot;
	int flags;
};

struct fd_opened
{
	char filename[512]; // 512 is max path we use
	std::vector<int> fds;
	int shared_fd;
	uintptr_t start_ptr;
	int mmap_count;
	// size_t size; -> WE USE MAX_FILE_SIZE to handle potential fragmantation issues
	std::vector<protection_data> prots;
};

static std::vector<fd_opened> g_fd_open;
// static std::vector<fd_mapping> g_file_mappings;

// guard against double initializations requests from users
static bool g_storage_is_initialized = false;

// Page table (maps file frames to EPC cache)
storage::PageTable* g_storage_page_table;

uintptr_t g_base_storage_bs_ptr = 0;

static struct page_cache g_storage_page_cache;

// base pointer to the Page Cache (PC)
uintptr_t g_storage_base_page_cache_ptr;

#ifdef STORAGE_DECRYPT

// I/O key
//
sgx_aes_gcm_128bit_key_t g_storage_key;

#endif

// cleanup request for data structures unused stack memory
int storage_mstore_cleanup()
{
	cleanup_page_cache(&g_storage_page_cache);
	g_storage_page_table->cleanup();

	return 0;
}

int storage_mstore_init(void* priv_data)
{
	// Note: priv_data should contain the file paths we look for

	// Protect from double initializations
	if (g_storage_is_initialized)
	{
		return -1;
	}

	// ASSERT(ptr_pool != NULL);

#ifdef STORAGE_DECRYPT
	// Hard coded for now. Practically should be passed from a trusted source (as discussed in the Haven paper)
	//
	memset(g_storage_key, 0, SGX_AESGCM_KEY_SIZE);
#endif

	g_base_storage_bs_ptr = 0;
	g_storage_page_table = new storage::PageTable(/*num_of_buckets=*/STORAGE_PAGE_CACHE_NUM_OF_ENTRIES * 10, STORAGE_PAGE_CACHE_NUM_OF_ENTRIES);
	init_page_cache(&g_storage_page_cache, &g_storage_base_page_cache_ptr, STORAGE_PAGE_CACHE_SIZE, STORAGE_PAGE_SIZE);

	// for (int i=0;i<STORAGE_TLB_SIZE;i++)
	// {
	// 	gt_STORAGE_TLB[i].bs_page_index = -1;
	// }

	g_storage_is_initialized = true;

	return 0;
}

/*
inline void change_tlb_storage(int bs_page_index, int epc_page_index, char dirty) 
{
	// Decrease ref count since no one else in this thread is currently using this value
	// No need for lock because its per thread
	//
	int removed_page_index = gt_STORAGE_TLB[STORAGE_TLB_SIZE-1].bs_page_index;

	if (removed_page_index >= 0)
	{
		uintptr_t removed_bs_ptr = removed_page_index * COSMIX_PAGE_SIZE;
		for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
		{
			if (it->start_ptr <= removed_bs_ptr && (it->start_ptr+MAX_FILE_SIZE) > removed_bs_ptr)
			{
				int removed_fd = it->shared_fd;
				g_storage_page_table->update_entry(removed_fd, removed_page_index, gt_STORAGE_TLB[STORAGE_TLB_SIZE-1].is_dirty, -1);
				break;
			}
		}
	}

	memmove(&gt_STORAGE_TLB[1], &gt_STORAGE_TLB[0], sizeof(struct s_victim_cache) * (STORAGE_TLB_SIZE-1));

	gt_STORAGE_TLB[0].bs_page_index = bs_page_index;
	gt_STORAGE_TLB[0].epc_page_index = epc_page_index;
	gt_STORAGE_TLB[0].is_dirty = dirty;
}
*/

// Eviction of page from the PageTable.
// Note: eviction heuristic is implemented in the PageTable class
unsigned char* try_evict_page_storage(storage::item_t* pce)
{
	unsigned char* epc_page_ptr = (unsigned char*)(g_storage_base_page_cache_ptr + (pce->epc_page_index * STORAGE_PAGE_SIZE));

	// if the page is dirty (was written to)
	//
	if (pce->is_dirty)
	{
		uintptr_t bs_ptr =  pce->page_index * STORAGE_PAGE_SIZE;
		// Note: should already be aligned to start of a page
		off_t file_offset = bs_ptr & (MAX_FILE_SIZE-1);
		
		// Use thread-local untrusted buffer to encrypt into. Write that one - integrity for now is not dealt wit?
#ifdef STORAGE_DECRYPT
		unsigned char temp_buf[STORAGE_PAGE_SIZE];
		
		// Note: for now we do not handle file's integrity
		//
		unsigned char nonce[12];
		memset(nonce, 0, 12);
		sgx_aes_gcm_128bit_tag_t mac;
		memset(mac, 0, SGX_AESGCM_MAC_SIZE);

		// Encrypt from the page cache (epc_page_ptr) to a temp buf, which would be written to the FS
		//
		sgx_status_t ret = sgx_rijndael128GCM_encrypt(&g_storage_key,
					epc_page_ptr,
					STORAGE_PAGE_SIZE,
					temp_buf,
					nonce,
					12,
					NULL,
					0,
					&mac);

		ASSERT (ret == SGX_SUCCESS);
		int n = _real_pwrite(pce->fd, (void*)temp_buf, STORAGE_PAGE_SIZE, offset);
		ASSERT(n == STORAGE_PAGE_SIZE);
#else
		int n = _real_pwrite(pce->fd, (void*)epc_page_ptr, STORAGE_PAGE_SIZE, file_offset);
		ASSERT(n == STORAGE_PAGE_SIZE);
#endif
	}

	g_storage_page_table->remove(pce->fd, pce->page_index);

	return epc_page_ptr;
}

void* storage_mpf_handler_c(void* ptr)
{
	// ptr is always in MAX_FILE_SIZE granularity. offset in page is based on PAGE_SIZE.
	// page table is always page index + shared_fd
	uintptr_t bs_ptr = (uintptr_t)ptr;
	int fd;
	int page_index = (bs_ptr & (MAX_FILE_SIZE-1)) / STORAGE_PAGE_SIZE;
	int page_offset = bs_ptr & (STORAGE_PAGE_SIZE-1);
	// off_t offset;

	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{
		if (it->start_ptr <= bs_ptr && (it->start_ptr+MAX_FILE_SIZE) > bs_ptr)
		{
			fd = it->shared_fd;
			break;
		}
	}

	// Get operation will increment the ref count if an entry exists. It will be decremented when removed from the TLB
	//
    storage::item_t* it = g_storage_page_table->get(fd, page_index);

    if (it)
    {
	    uintptr_t res = g_storage_base_page_cache_ptr + (it->epc_page_index * STORAGE_PAGE_SIZE) + page_offset;

	    return (void*)res;
    }

	unsigned char* free_epc_ptr = pop_free_page(&g_storage_page_cache);

	// No page available, need to evict
	if (free_epc_ptr == nullptr)
    {
        storage::item_t* page_to_evict = g_storage_page_table->get_page_index_to_evict();
        free_epc_ptr = try_evict_page_storage(page_to_evict);
    }

    int free_epc_page_index = ((uintptr_t)free_epc_ptr - g_storage_base_page_cache_ptr) / STORAGE_PAGE_SIZE;	
	int file_index = bs_ptr / MAX_FILE_SIZE;
	off_t file_offset = bs_ptr & (MAX_FILE_SIZE-1);
	// align to start of a page
	//
	file_offset = file_offset & ~(STORAGE_PAGE_SIZE-1);

#ifdef STORAGE_DECRYPT
	unsigned char temp_buf[STORAGE_PAGE_SIZE];
	
	// Note: for now we do not handle file's integrity
	//
	unsigned char nonce[12];
	memset(nonce, 0, 12);
	sgx_aes_gcm_128bit_tag_t mac;
	memset(mac, 0, SGX_AESGCM_MAC_SIZE);

	int n = _real_pread(fd, (void*)temp_buf, STORAGE_PAGE_SIZE, offset);
	ASSERT(n == STORAGE_PAGE_SIZE);

	// Now - decrypt from the temp_buf to the page cache (free_epc_ptr)
	//
	sgx_status_t ret = sgx_rijndael128GCM_decrypt(&g_storage_key,
				temp_buf,
				STORAGE_PAGE_SIZE,
				free_epc_ptr,
				nonce,
				12,
				NULL,
				0,
				&mac);

	ASSERT (ret == SGX_SUCCESS);
#else
	int n = _real_pread(fd, (void*)free_epc_ptr, STORAGE_PAGE_SIZE, file_offset);
	// ASSERT(n == STORAGE_PAGE_SIZE);
#endif
 
    // Try add to cache, if other sptr already added while we worked on it - just return it as a minor, and return our page to the free pages pool.
    if (!g_storage_page_table->try_add(fd, page_index, free_epc_page_index))
    {
        storage::item_t* found = g_storage_page_table->get(fd, page_index);
        ASSERT (found != NULL); // if NULL - abort! 

		push_free_page(&g_storage_page_cache, free_epc_ptr);
        free_epc_ptr = (unsigned char*)(g_storage_base_page_cache_ptr + (found->epc_page_index * STORAGE_PAGE_SIZE));
    }

    unsigned char* res = free_epc_ptr + page_offset;

    free_epc_page_index = ((uintptr_t)free_epc_ptr - g_storage_base_page_cache_ptr) / STORAGE_PAGE_SIZE;
    //g_debug("mpf res %p ps %d ss %d\n", res, STORAGE_PAGE_SIZE, STORAGE_PAGE_CACHE_SIZE);
/*
	int volatile a = 0;
    for(int i = 0; i < 10539778; i++)
		a += res[i];
*/
    return res;
}

// void* page_fault_storage(void* ptr, char dirty) {
// 	return page_fault_storage_internal(ptr, dirty);
// }

// TODO: lock all of these
void storage_mstore_open(char* filename, int fd, char always_register_fd, char* registered_fd)
{
	*registered_fd = 0;

	// In case this file is not needed, just return
	//
	bool register_fd = strcmp(filename, STORAGE_MMAP_FILE_PATH) == 0;
	if (!always_register_fd && !register_fd)
	{
		return;
	}

	// Notify the user that we registered this fd
	//
	*registered_fd = 1;

	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{
		if (strcmp(it->filename, filename) == 0)
		{
			// found it, add fd to entry
			it->fds.push_back(fd);
			return;
		}
	}

	// otherwise, add a new entry
	fd_opened entry;
	strcpy(entry.filename, filename);
	entry.fds.push_back(fd);
	entry.start_ptr = g_base_storage_bs_ptr;
	entry.mmap_count = 0;
	g_base_storage_bs_ptr += MAX_FILE_SIZE;
	// make sure we register a single shraed_fd that every opened fd to the same inode would use as a key for the page table
	//
	entry.shared_fd = _real_open(filename, O_RDWR);
	ASSERT(entry.shared_fd);

	g_fd_open.push_back(entry);
}

void storage_mstore_close(int fd)
{
	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{
		// first check if its the single entry
		if (it->fds.size() == 1 && it->mmap_count == 0 && it->fds[0] == fd)
		{
			// earse the entire entry
			_real_close(it->shared_fd);
			g_fd_open.erase(it);
			return;
		}

		for (auto it_fd = it->fds.begin(); it_fd != it->fds.end(); it_fd++)
		{
			if (*it_fd == fd)
			{
				// found it remove it and exit
				it->fds.erase(it_fd);
				return;
			}
		}
	}
}

// return the base ptr, if it exists. if not return 0 (NULL)
uintptr_t storage_get_base_ptr_for_fd(int fd)
{
	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{
		for (auto it_fd = it->fds.begin(); it_fd != it->fds.end(); it_fd++)
		{
			if (*it_fd == fd)
			{
				return it->start_ptr;
			}
		}
	}

	return -1;
}

void storage_munmap(void* bs_ptr)
{
	uintptr_t ptr = (uintptr_t)bs_ptr;
	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{
		// in range
		if (it->start_ptr <= ptr && (it->start_ptr+MAX_FILE_SIZE) > ptr)
		{
			it->mmap_count--;
			if (it->mmap_count == 0 && it->fds.size() == 0)
			{
				close(it->shared_fd);
				g_fd_open.erase(it);
			}
		}
	}
}

void storage_mmap(void* bs_ptr)
{
	// TODO: register protection bits
	uintptr_t ptr = (uintptr_t)bs_ptr;
	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{
		// in range
		if (it->start_ptr <= ptr && (it->start_ptr+MAX_FILE_SIZE) > ptr)
		{
			it->mmap_count++;
		}
	}
}

void storage_mremap(void* old, size_t new_len, int flags)
{
	// TODO: change protection bits
}

ssize_t storage_mstore_read(int fd, void* buf, size_t count)
{
	// otherwise, use storage read
	// add correct offset 	
	uintptr_t storage_ptr;
	int shared_fd;

	bool found = false;
	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{		
		for (auto it_fd = it->fds.begin(); it_fd != it->fds.end(); it_fd++)
		{
			if (*it_fd == fd)
			{
				storage_ptr = it->start_ptr;
				shared_fd = it->shared_fd;
				found = true;
				break;
			}
		}

		if (found)
		{
			break;
		}
	}

	if (!found)
	{
		return _real_read(fd, buf, count);
	}

	off_t offset = lseek(fd, 0, SEEK_CUR);
	storage_ptr += offset;
	// go page by page according to count
	char* dest = (char*)buf;
	struct stat st;
	fstat(fd, &st);
	
	ssize_t reamining_bytes_in_file = st.st_size - offset;
	ssize_t total_read = reamining_bytes_in_file > count ? count : reamining_bytes_in_file;
	count = total_read;

	while (count > 0)
	{
		int page_offset = storage_ptr & (STORAGE_PAGE_SIZE-1);
		int remain = STORAGE_PAGE_SIZE - page_offset;
		if (count < remain)
		{
			remain = count;
		}

		void* storage_cache_ptr = storage_mpf_handler_c((void*)storage_ptr);				
		memcpy(dest, storage_cache_ptr, remain);		

		int page_index = (storage_ptr & (MAX_FILE_SIZE-1)) / STORAGE_PAGE_SIZE;

		g_storage_page_table->update_entry(shared_fd, page_index, 0, -1);

		dest += remain;
		storage_ptr += remain;
		count -= remain;
	}

	// Advance the cursor correctly
	//
	lseek(fd, total_read, SEEK_CUR);

	return total_read;
}

ssize_t storage_mstore_write(int fd, void* buf, size_t count)
{	
	// otherwise, use storage read
	// add correct offset 	
	uintptr_t storage_ptr;
	int shared_fd;

	bool found = false;
	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{		
		for (auto it_fd = it->fds.begin(); it_fd != it->fds.end(); it_fd++)
		{
			if (*it_fd == fd)
			{
				storage_ptr = it->start_ptr;
				shared_fd = it->shared_fd;
				found = true;
				break;
			}
		}

		if (found)
		{
			break;
		}
	}


	if (!found)
	{
		return _real_write(fd, buf, count);
	}

	off_t offset = lseek(fd, 0, SEEK_CUR);
	storage_ptr += offset;

	// go page by page according to count
	char* src = (char*)buf;
	ssize_t total_write = count;

	while (count > 0)
	{
		int page_offset = storage_ptr & (STORAGE_PAGE_SIZE-1);
		int remain = STORAGE_PAGE_SIZE - page_offset;
		if (count < remain)
		{
			remain = count;
		}

		void* storage_cache_ptr = storage_mpf_handler_c((void*)storage_ptr);
		memcpy(storage_cache_ptr, src, remain);
		
		int page_index = (storage_ptr & (MAX_FILE_SIZE-1)) / STORAGE_PAGE_SIZE;

		g_storage_page_table->update_entry(shared_fd, page_index, 1, -1);

		src += remain;
		storage_ptr += remain;
		count -= remain;
	}

	// Finally, also propagate the change to the fd and update the cursor
	//
	ssize_t total_write_fd = _real_write(fd, buf, total_write);
	ASSERT(total_write == total_write_fd);

	return total_write;
}

void storage_msync(void *addr, size_t length, int flags)
{
	// Go over the cache and evict all
}

void storage_sync()
{
	// sync all
}

void storage_fsync(int fd)
{
/*
	// sync all pages of fd
	auto used_pages = g_storage_page_table->GetUsedPages();
	// go over all entries
	do
	{
		int entry_fd;
		int page_index;
		used_pages->dequeue(&entry_fd, &page_index);

		if (fd == entry_fd)
		{
			// write-back

		}

		bucket& bkt = m_buckets[page_index % m_hashmap_size];
		spin_lock(&bkt.lock);

		item_t* it = get_internal(fd, page_index);

		if (it->ref_count > 0)
		{
			spin_unlock(&bkt.lock);
			m_used_pages->enqueue(fd ,page_index);
			num_of_tries++;
		}
		else
		{                    
			ASSERT (it != NULL);
			return it;
		}
	} while (true);
*/

	// Done, unlock and return
}

void storage_sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags)
{
	// sync requested parts of fd
}

void storage_notify_tlb_cached(void* ptr)
{
	// Note: PF already increases reference count for this page, which locks the pte.
	// so no need to do anything here.
}

// IDea: keep removing MAX_FILE_SIZE until pointer reaches zero. Then look at its bounds (page index in this case).
// For getting g_mstorage, do the same, but it will need to take the pointer itself

void storage_notify_tlb_dropped(void* ptr, bool dirty)
{
	uintptr_t removed_bs_ptr = (uintptr_t)ptr; 
	int removed_page_index = storage_mstore_get_mstorage_page(removed_bs_ptr) >> STORAGE_PAGE_BITS;

	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{
		if (it->start_ptr <= removed_bs_ptr && (it->start_ptr+MAX_FILE_SIZE) > removed_bs_ptr)
		{
			int removed_fd = it->shared_fd;
			g_storage_page_table->update_entry(removed_fd, removed_page_index, dirty, -1);
			break;
		}
	}
}

void* storage_mstore_alloc(size_t size, void* private_data)
{
	struct s_file_alloc_privdata* file_alloc_privdata = (struct s_file_alloc_privdata*)private_data;
	ASSERT(file_alloc_privdata);
	uintptr_t fd_base_ptr = 0;

	bool found = false;

	// TODO: register protection bits
	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{
		for (auto it_fd = it->fds.begin(); it_fd != it->fds.end(); it_fd++)
		{
			if (*it_fd == file_alloc_privdata->fd)
			{
				it->mmap_count++;
				fd_base_ptr = it->start_ptr;
				found = true;
				break;
			}
		}

		if (found)
		{
			break;
		}
	}

	if (!found)
	{
		file_alloc_privdata->alloc_succeeded = 0;
		return nullptr;
	}

	file_alloc_privdata->alloc_succeeded = 1;
	return (void*)(fd_base_ptr + file_alloc_privdata->off);
}

size_t storage_mstore_alloc_size(void* ptr)
{
	// mmap size
	g_debug("storage_mstore_alloc_size not yet supported\n");
	abort();
	return 0;
}

void storage_mstore_free(void* fd_ptr)
{
	uintptr_t ptr = (uintptr_t)fd_ptr;
	for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
	{
		// in range
		if (it->start_ptr <= ptr && (it->start_ptr+MAX_FILE_SIZE) > ptr)
		{
			it->mmap_count--;
			if (it->mmap_count == 0 && it->fds.size() == 0)
			{
				close(it->shared_fd);
				g_fd_open.erase(it);
			}
		}
	}
}

void storage_flush(void* ptr, size_t size)
{
	unsigned char* start_page = (unsigned char*)((uintptr_t)ptr & ~STORAGE_PAGE_OFFSET_MASK);
	for (unsigned i=0; i<size; i+=STORAGE_PAGE_SIZE)
	{
		unsigned char* curr_page = start_page + i * STORAGE_PAGE_SIZE;
		int bs_page_index = ((uintptr_t)curr_page - g_base_storage_bs_ptr) >> STORAGE_PAGE_BITS;

		// lookup backing store page
		int fd;
		for (auto it = g_fd_open.begin(); it != g_fd_open.end(); it++)
		{
			if (it->start_ptr <= (uintptr_t)curr_page && (it->start_ptr+MAX_FILE_SIZE) > (uintptr_t)curr_page)
			{
				fd = it->shared_fd;
				break;
			}
		}
		storage::item_t* it = g_storage_page_table->get(fd, bs_page_index);
    	bool is_minor = it != NULL;
    	if (is_minor) {
			// found it, sync to storage
			unsigned char* epc_page_ptr = (unsigned char*)(g_storage_base_page_cache_ptr + (it->epc_page_index * STORAGE_PAGE_SIZE));
			off_t file_offset = ((uintptr_t)curr_page & (MAX_FILE_SIZE-1));
			int n = _real_pwrite(fd, (void*)epc_page_ptr, STORAGE_PAGE_SIZE, file_offset);
			ASSERT(n == STORAGE_PAGE_SIZE);
		}
	}
}

// Encapsulate mstorage, mpage_cache, and mpage_size
uintptr_t storage_mstore_get_mpage_cache_base_ptr()
{
	return g_storage_base_page_cache_ptr;
}

uintptr_t storage_mstore_get_mstorage_page(uintptr_t ptr)
{
	// Zero out all higher bits representing the fds in our implementation
	//
	return (ptr & (MAX_FILE_SIZE-1));
}

size_t storage_mstore_get_mpage_size()
{
	return STORAGE_PAGE_SIZE;
}

int storage_mstore_get_mpage_bits()
{
	return STORAGE_PAGE_BITS;
}
