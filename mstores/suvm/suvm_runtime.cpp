/*
 * Runtime for SUVM
 */
#include "suvm_runtime.h"
#include "../common/mem_allocator.h"
#include "../common/SyncUtils.h"
#include "../common/PageTable.h"
#include "../common/page_cache.h"
#include "../common/mstore_common.h"
#include "../../include/common.h"
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>      /* vsnprintf */
#include <vector>
#include <assert.h>
#include  <math.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <time.h>

#ifndef SDK_BUILD
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

static pthread_cond_t cv;
static pthread_mutex_t lock;

#else
extern "C" void ocall_untrusted_alloc(void** umem, size_t size);

#endif

long long g_major_faults = 0;
long long g_minor_faults = 0;
long long g_inc_ref_num = 0;
long long g_unlink_num = 0;
long long g_evictions = 0;

// Maximum number of entries we support to be evicted simultaneously 
const int MAX_NUM_OF_THREADS_OPTIMIZATION = 10;
// SUVM's paging key - randomly generated at initialization
sgx_aes_gcm_128bit_key_t g_eviction_key;

// guard against double initializations requests from users
bool g_is_initialized = 0;

// Page table (maps SUVM backing store to EPC cache and vise versa)
PageTable* g_page_table;

// base pointer to the Backing Store (BS)
uintptr_t g_base_suvm_bs_ptr = 0;

static struct page_cache g_suvm_page_cache;

// base pointer to the Page Cache (PC)
uintptr_t g_suvm_base_page_cache_ptr;

// base pointer to the MACs stored in the backing store
sgx_mac_t* g_mac_base_ptr;

// base pointer to the Nonces stored in trusted mem
unsigned char* g_nonce_base_ptr;

volatile char* volatile m_ref_count;

// cleanup request for data structures unused stack memory
int suvm_mstore_cleanup()
{
	cleanup_page_cache(&g_suvm_page_cache);
	g_page_table->cleanup();
	free(g_nonce_base_ptr);
	free((void*)m_ref_count);

	return 0;
}

#ifndef SDK_BUILD

extern "C" sgx_status_t sgx_init_crypto_lib(uint64_t cpu_feature_indicator);

#endif

void* evict_thread(void *v);

void* allocate_untrusted_buffer(size_t size)
{
	// Note: we always allocate with extra HW PAGE to later align to hardware pages for better performance.
	//
	size_t alloc_size = size + 0x1000;
	void* bs_ptr = NULL;

#ifdef SDK_BUILD
	ocall_untrusted_alloc(&bs_ptr, alloc_size);
#elif ANJUNA_BUILD
#warning Using alloc_untrusted system call exported by Anjuna Runtime
	int ret = syscall(346, alloc_size, &bs_ptr);
	if (ret < 0 || bs_ptr == NULL) {
		printf("Failed allocating untrusted memory (%d)\n", ret);
		exit(-1)
	}
#elif GRAPHENE_BUILD
#warning Using alloc_untrusted system call exported by a modified Graphene-SGX version
	int ret = syscall(310, alloc_size, &bs_ptr);
    	if (ret < 0 || bs_ptr == NULL) {
        	printf("Failed allocating untrusted memory (%d)\n", ret);
			exit(-1);
    	}
#else
	// Note: workaround for SCONE. They don't have page cache, 
	// so allocating annonymous memory backed by "a file" will actually be untrusted memory
	//
	int fd = _real_open("/dev/zero", O_RDWR);
	bs_ptr = mmap(0, alloc_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	_real_close(fd);

	ASSERT (bs_ptr != MAP_FAILED);	
#endif
	ASSERT (bs_ptr);
	return bs_ptr;
}

// int mstore_init(uintptr_t * runtime_bs_ptr, uintptr_t* runtime_cache_ptr)
int suvm_mstore_init(void* priv_data)
{
	// Protect from double initializations
	if (g_is_initialized)
	{
		return -1;
	}

#ifndef SDK_BUILD
	
    uint64_t mask = 0;
    mask |= 0x00000001;
    mask |= 0x00000002;
    mask |= 0x00000004;
    mask |= 0x00000008;
    mask |= 0x00000010;
    mask |= 0x00000020;
    mask |= 0x00000040;
    mask |= 0x00000200;
    mask |= 0x00000800;
    mask |= 0x00002000;
    mask |= 0x00004000;
    mask |= 0x00008000;
    mask |= 0x00010000;
    mask |= 0x00020000;
    mask |= 0x00040000;

    mask |= 0x00000400; //aes;
    mask |= 0x00000080; //sse4.2
    mask |= 0x00000100; //avx;
    sgx_init_crypto_lib(mask);

#endif

	const size_t num_bs_entries = SUVM_BS_SIZE / SUVM_PAGE_SIZE;
	const size_t bs_mac_size = MAC_BYTE_SIZE * num_bs_entries;
	void* bs_ptr = allocate_untrusted_buffer(SUVM_BS_SIZE+bs_mac_size);
	int rc = Untrustedmemsys5Init(NULL, bs_ptr, SUVM_BS_SIZE, MN_REQ);
	ASSERT (rc == 0);

	g_base_suvm_bs_ptr = (uintptr_t)bs_ptr;
	g_mac_base_ptr = (sgx_mac_t*)((char*)bs_ptr + SUVM_BS_SIZE);

	m_ref_count = (volatile char* volatile)_real_malloc(num_bs_entries * 2 * sizeof(char));
	memset((void*)m_ref_count, 0, num_bs_entries * 2 * sizeof(char));

	g_page_table = new PageTable(/*num_of_buckets=*/(SUVM_PAGE_CACHE_SIZE/SUVM_PAGE_SIZE) * 10,/*backing_store_size=*/num_bs_entries, /*page cache size=*/ (SUVM_PAGE_CACHE_SIZE/SUVM_PAGE_SIZE));
	g_nonce_base_ptr = (unsigned char*)_real_malloc((NONCE_BYTE_SIZE+1)*num_bs_entries);
	ASSERT(g_nonce_base_ptr);
	memset(g_nonce_base_ptr, 0, (NONCE_BYTE_SIZE+1)*num_bs_entries);

	init_page_cache(&g_suvm_page_cache, &g_suvm_base_page_cache_ptr, SUVM_PAGE_CACHE_SIZE, SUVM_PAGE_SIZE);

	// Init suvm's encryption key by using HW-assited random values generator
#ifdef SDK_BUILD
	sgx_read_rand(g_eviction_key, (uint64_t)sizeof(sgx_aes_gcm_128bit_key_t));
#else
	srand(time(0));
	for (unsigned int i = 0; i <sizeof(sgx_aes_gcm_128bit_key_t); i++)
	{
		g_eviction_key[i] = rand();
	}
#endif

#ifndef SDK_BUILD
#ifdef ASYNC_EVICTS
#warning "### SUVM ENABLED ASYNC EVICTS ###"
	int ret = pthread_cond_init(&cv, NULL);
	ASSERT(!ret);
	ret = pthread_mutex_init(&lock, NULL);
	ASSERT(!ret);

	pthread_t t;
	ret = pthread_create(&t, NULL, evict_thread, NULL);
	ASSERT(!ret);
#endif
#endif

	g_is_initialized = 1;
	return 0;
}

// Eviction of page from the PageTable.
// Note: eviction heuristic is implemented in the PageTable class
unsigned char* try_evict_page(item_t* pce)
{
	int page_index = pce->bs_page_index;
	unsigned char* epc_page_ptr = (unsigned char*)(g_suvm_base_page_cache_ptr + (pce->epc_page_index * SUVM_PAGE_SIZE));

	// if the page is dirty (was written to)
	//
	if (m_ref_count[page_index*2+1])
	{
		INC_COUNTER(g_evictions);
		m_ref_count[page_index*2+1] = 0;

		unsigned char* nonce = &g_nonce_base_ptr[page_index*(NONCE_BYTE_SIZE+1)];
		nonce[NONCE_BYTE_SIZE]=1;
		
		sgx_aes_gcm_128bit_tag_t* mac = &g_mac_base_ptr[page_index];
#ifdef SDK_BUILD
		sgx_read_rand(nonce, NONCE_BYTE_SIZE);
#else
		// Nonce is 12 bytes and int is 4 bytes
		//
		int* nonce_casted = (int*)nonce;
		nonce_casted[0] = rand();
		nonce_casted[1] = rand();
		nonce_casted[2] = rand();
#endif
		unsigned char* ram_page_ptr = (unsigned char*)(g_base_suvm_bs_ptr + page_index * SUVM_PAGE_SIZE);
		
		sgx_status_t ret = sgx_rijndael128GCM_encrypt(&g_eviction_key,
				epc_page_ptr,
				SUVM_PAGE_SIZE,
				ram_page_ptr,
				nonce,
				NONCE_BYTE_SIZE,
				NULL,
				0,
				mac);

		ASSERT (ret == SGX_SUCCESS);	
	}

	g_page_table->remove(page_index);
	
	// written back encrypted data - done return
	//
	return epc_page_ptr;
}

// Page fault routine - gets a pointer to the BS and returns a pointer to SUVM's cache in EPC.
void* suvm_mpf_handler_c(void* bs_page) {
	int bs_page_index = ((uintptr_t)bs_page - g_base_suvm_bs_ptr) >> SUVM_PAGE_BITS;
	int page_offset = ((uintptr_t)bs_page - g_base_suvm_bs_ptr) & SUVM_PAGE_OFFSET_MASK;
	char dirty = 0; // non-dirty by default

	// Increase it. It is decreased when it gets evicted from the TLB
	//
	__sync_fetch_and_add( &m_ref_count[bs_page_index*2], 1);

    item_t* it = g_page_table->get(bs_page_index, dirty);
    bool is_minor = it != NULL;
    if (is_minor)
    {

    	INC_COUNTER(g_minor_faults);
    	uintptr_t res = g_suvm_base_page_cache_ptr + (it->epc_page_index * SUVM_PAGE_SIZE) + page_offset;

        return (void*)res;
    }

    INC_COUNTER(g_major_faults);


	unsigned char* free_epc_ptr = pop_free_page(&g_suvm_page_cache);

	// No page available, need to evict
	if (free_epc_ptr == nullptr)
	{
#ifndef SDK_BUILD
#ifdef ASYNC_EVICTS
		//wakeup_thread;
		pthread_cond_signal(&cv);
#endif
#endif

		item_t* page_to_evict = g_page_table->get_page_index_to_evict(m_ref_count);
	        free_epc_ptr = try_evict_page(page_to_evict);
		
	}

    int free_epc_page_index = ((uintptr_t)free_epc_ptr - g_suvm_base_page_cache_ptr) / SUVM_PAGE_SIZE;

    unsigned char* nonce = &g_nonce_base_ptr[bs_page_index*(NONCE_BYTE_SIZE+1)]; //crypto_item->nonce;
    if (nonce[NONCE_BYTE_SIZE]) // page was swapped out. Decrypt it back in.
    {
        unsigned char* ram_page_ptr = (unsigned char*)(g_base_suvm_bs_ptr + bs_page_index * SUVM_PAGE_SIZE);
        sgx_aes_gcm_128bit_tag_t* mac = &g_mac_base_ptr[bs_page_index];

		sgx_status_t ret = sgx_rijndael128GCM_decrypt(&g_eviction_key,
				ram_page_ptr,
				SUVM_PAGE_SIZE,
				free_epc_ptr,
				nonce,
				NONCE_BYTE_SIZE,
				NULL,
				0,
				mac);

		ASSERT (ret == SGX_SUCCESS);
    }

    // Try add to cache, if other sptr already added while we worked on it - just return it as a minor, and return our page to the free pages pool.
    if (!g_page_table->try_add(bs_page_index, free_epc_page_index, dirty))
    {
        item_t* found = g_page_table->get(bs_page_index, dirty);
        ASSERT (found != NULL); // if NULL - abort! 

	push_free_page(&g_suvm_page_cache, free_epc_ptr);
        free_epc_ptr = (unsigned char*)(g_suvm_base_page_cache_ptr + (found->epc_page_index * SUVM_PAGE_SIZE));
    }

    unsigned char* res = free_epc_ptr + page_offset;

    return res;
}

#ifndef SDK_BUILD
void* evict_thread(void *v) {
	pthread_mutex_lock(&lock);
	while (1) {
		pthread_cond_wait(&cv, &lock);

		// Woken up - meaning we got a new request
		int num_of_pages_to_free = EVICT_CACHE_THRESHOLD - g_suvm_page_cache.m_num_of_free_pages;
		if (num_of_pages_to_free > 0) {

			for (int i=0;i<num_of_pages_to_free;i++)
			{
				item_t* page_to_evict = g_page_table->get_page_index_to_evict(m_ref_count);
				unsigned char* free_epc_ptr = try_evict_page(page_to_evict);
				push_free_page(&g_suvm_page_cache, free_epc_ptr);	
			}
		}

		//pthread_mutex_unlock(&lock);	
	}

	return NULL;
}
#endif

// Debug method to validate reference count is zero for all pages in the PageTable. Expected to be called in the end of the encalve life.
void debug_ref_count()
{
	int res = g_page_table->debug_ref_count(m_ref_count);
	if (res > 5) {
		g_debug("Found %d ref count\n", res);
	}

#ifndef NO_COUNTERS
	g_debug("Number of faults: minor %lld, major %lld, evictions: %lld\n", g_minor_faults, g_major_faults, g_evictions);
	g_debug("Number of inc_ref_count: %lld, unlink %lld\n", g_inc_ref_num, g_unlink_num);
#endif
}

// Flushes the relavent pages to the backing store (untrusted memory)
void suvm_flush(void* ptr, size_t size)
{
	unsigned char* start_page = (unsigned char*)((uintptr_t)ptr & ~SUVM_PAGE_OFFSET_MASK);
	for (unsigned i=0; i<size; i+=SUVM_PAGE_SIZE)
	{
		unsigned char* curr_page = start_page + i * SUVM_PAGE_SIZE;
		int bs_page_index = ((uintptr_t)curr_page - g_base_suvm_bs_ptr) >> SUVM_PAGE_BITS;

		// lookup backing store page
		item_t* it = g_page_table->get(bs_page_index, 0);
    	bool is_minor = it != NULL;
    	if (is_minor) {
			// found it, evict
			unsigned char* nonce = &g_nonce_base_ptr[bs_page_index*(NONCE_BYTE_SIZE+1)];
			sgx_aes_gcm_128bit_tag_t* mac = &g_mac_base_ptr[bs_page_index];
#ifdef SDK_BUILD
			sgx_read_rand(nonce, NONCE_BYTE_SIZE);
#else
			// Nonce is 12 bytes and int is 4 bytes
			//
			int* nonce_casted = (int*)nonce;
			nonce_casted[0] = rand();
			nonce_casted[1] = rand();
			nonce_casted[2] = rand();
#endif
			unsigned char* epc_page_ptr = (unsigned char*)(g_suvm_base_page_cache_ptr + it->epc_page_index * SUVM_PAGE_SIZE);
			sgx_status_t ret = sgx_rijndael128GCM_encrypt(&g_eviction_key,
					epc_page_ptr,
					SUVM_PAGE_SIZE,
					curr_page,
					nonce,
					NONCE_BYTE_SIZE,
					NULL,
					0,
					mac);

			ASSERT (ret == SGX_SUCCESS);
		}
	}
}

void suvm_notify_tlb_cached(void* ptr)
{
	// Note: PF already increases reference count for this page, which locks the pte.
	// so no need to do anything here.
}

// Reduces reference count for this page
void suvm_notify_tlb_dropped(void* ptr, bool dirty)
{
	int removed_page_index = ((uintptr_t)ptr - g_base_suvm_bs_ptr) >> SUVM_PAGE_BITS;
	__sync_fetch_and_add( &m_ref_count[removed_page_index*2], -1);
	m_ref_count[removed_page_index*2+1] |= dirty;
}

void* suvm_mstore_alloc(size_t size, void* private_data)
{
	return Untrustedmemsys5Malloc(size);
}

void suvm_mstore_free(void* ptr)
{
	Untrustedmemsys5Free(ptr);
}

size_t suvm_mstore_alloc_size(void* ptr)
{
	// Note: the management of alloc size should move to the runtime, but this needs to be refactored out of the allocator logic,
	// otherwise it would be a duplicated logic (simple implementation of allocating extra 8 bytes and saving the length there).
	size_t res = Untrustedmemsys5Size(ptr);

	return res;
}

uintptr_t suvm_mstore_get_mpage_cache_base_ptr()
{
	return g_suvm_base_page_cache_ptr;
}

uintptr_t suvm_mstore_get_mstorage_page(uintptr_t ptr)
{
	return ptr - g_base_suvm_bs_ptr;
}

size_t suvm_mstore_get_mpage_size()
{
	return SUVM_PAGE_SIZE;
}

int suvm_mstore_get_mpage_bits()
{
	return SUVM_PAGE_BITS;
}

static void * (* const volatile __memset_vp)(void *, int, size_t)
    = (memset);

#ifndef SDK_BUILD

#include <errno.h>

#ifdef memset_s
#undef memset_s /* in case it was defined as a macro */
#endif

#ifdef __cplusplus
extern "C"
#endif
int memset_s(void *s, size_t smax, int c, size_t n)
{
    int err = 0;

    if (s == NULL) {
        err = EINVAL;
        goto out;
    }

    if (n > smax) {
        err = EOVERFLOW;
        n = smax;
    }

    /* Calling through a volatile pointer should never be optimised away. */
    (*__memset_vp)(s, c, n);

    out:
    if (err == 0)
        return 0;
    else {
        errno = err;
        /* XXX call runtime-constraint handler */
        return err;
    }
}

#ifdef __cplusplus
extern "C"
#endif
int
consttime_memequal(const void *b1, const void *b2, size_t len)
{
	const unsigned char *c1 = (const unsigned char*)b1, *c2 = (const unsigned char*)b2;
	unsigned int res = 0;

	while (len--)
		res |= *c1++ ^ *c2++;

	/*
	 * Map 0 to 1 and [1, 256) to 0 using only constant-time
	 * arithmetic.
	 *
	 * This is not simply `!res' because although many CPUs support
	 * branchless conditional moves and many compilers will take
	 * advantage of them, certain compilers generate branches on
	 * certain CPUs for `!res'.
	 */
	return (1 & ((res - 1) >> 8));
}

#endif
