/* CoSMIX Runtime Layer */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "../include/common.h"

#ifndef SDK_BUILD

#include <strings.h>
#include <assert.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <utime.h>
#include <dirent.h>
#include <setjmp.h>
#include <mntent.h>
#include <libgen.h>
#include <getopt.h>
#include <ftw.h>
#include <poll.h>
#include <pthread.h>
#include <libintl.h>
#include <nl_types.h>
#include <iconv.h>
#include <locale.h>
#include <langinfo.h>
#include <monetary.h>
#include <wchar.h>
#include <semaphore.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timeb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/sem.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <malloc.h>

#endif

#ifdef ANJUNA_BUILD
#define __NR_alloc_untrusted (346)
#endif

#ifdef __cplusplus
extern "C" {
#endif


#define TRUE 1
#define FALSE 0

DBG_FUNC g_debug;

// TLB Section
#define TLB_SIZE 5

struct s_victim_cache {
	int32_t bs_page_index;
	uint16_t epc_page_index;
	uint8_t is_dirty;
};

// Helper functions typedefs
typedef int (*t_mem_function)(void*, void*, size_t);
typedef uintptr_t (*t_mem_function_single)(void*, int, size_t);

#ifdef JEMALLOC

extern void* je_malloc(size_t size);
extern void* je_calloc(size_t count, size_t size);
extern void* je_realloc(void* ptr, size_t size);
extern size_t je_malloc_usable_size(void* ptr);
extern void  je_free(void* ptr);

#endif

#ifdef TCMALLOC

extern void* tc_malloc(size_t size);
extern void* tc_calloc(size_t count, size_t size);
extern void* tc_realloc(void* ptr, size_t size);
extern void  tc_free(void* ptr);

#endif

// global print function - declared in common header
// DBG_FUNC g_debug;

__thread struct s_victim_cache gt_TLB[TLB_SIZE];

static __thread void* gt_direct_buffer;

// Optimization to not instrument file I/O libc wrappers if there is no mmap mstore in action for this application
//
static char g_storage_used = FALSE;

#define MAX_ACCESS_SIZE 64
__thread char gt_CrossPageBuffer[MAX_ACCESS_SIZE];
__thread uintptr_t gt_crosspage_access;
__thread int gt_crosspage_access_size;

static void* __cosmix_get_mstore_direct_buffer(size_t mpage_size)
{
	if (!gt_direct_buffer)
	{
		gt_direct_buffer = memalign(mpage_size, mpage_size);
		ASSERT(gt_direct_buffer);
	}

	return gt_direct_buffer;
}

/* Helper debugging functions */

#ifdef SDK_BUILD
extern void ocall_debug(const char* str);
extern void ocall_untrusted_alloc(void** ptr, size_t size);
#endif

void __cosmix_debug(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
#ifdef SDK_BUILD
	ocall_debug(buf);
#else
	fprintf(stderr,"%s", buf);
#endif
}

void __cosmix_initialize() 
{
#ifdef DBG_PRINT
	g_debug = __cosmix_debug; 
#endif	

	g_storage_used = FALSE;
}

void __cosmix_fail_asm(const void* arg)
{
	if (IS_COSMIX_PTR(arg)) 
	{
		g_debug("[ERROR] - Calling inline ASM with COSMIX pointer\n");
		abort();
	}
} 

void __cosmix_fail(const void* funcName, const void* arg) 
{
	if (IS_COSMIX_PTR(arg)) 
	{
		g_debug("[ERROR] - Calling a function without wrapper...exiting: %s %p\n", (char*)funcName, arg);
		abort();
	}
}

void __cosmix_test_atomic(const void* ptr)
{
	if (IS_COSMIX_PTR(ptr))
	{
		g_debug("[ERROR] - attempted to perform atomic operation on a COSMIX ptr...aborting\n");
		abort();
	}
}

// Helper function to validate all counters (and reference counters in the PT)
//
void __cosmix_debug_interal()
{
	// TODO: foreach cached-mstore call a helper method for debugging correct release of handlers
	// the compiler should insturment the debug methods for the actual mstore debug methods
	// debug_ref_count();
}

/* Forward declarations */
void* __cosmix_memset(void *dest, int c, size_t n);
int __cosmix_memcmp(const void *vl, const void *vr, size_t n);
void* __cosmix_memcpy(void *__restrict__ dest, const void *__restrict__ src, size_t n);
void* __cosmix_memmove(void *dest, const void *src, size_t n);

/* Init & Cleanup wrappers */

void* __cosmix_allocate_buffer(size_t size)
{
	// Note: we always allocate with extra HW PAGE to later align to hardware pages for better performance.
	//
	size_t alloc_size = size + 0x1000;
	void* bs_ptr = NULL;

#ifdef SDK_BUILD
	ocall_untrusted_alloc(&bs_ptr, alloc_size);
#elif ANJUNA_BUILD
#warning Using alloc_untrusted system call exported by Anjuna Runtime
	syscall(__NR_alloc_untrusted, alloc_size, &bs_ptr);
#else
	// Note: workaround for SCONE. They don't have page cache, 
	// so allocating annonymous memory backed by "a file" will actually be untrusted memory
	//
	int fd = open("/dev/zero", O_RDWR);
	bs_ptr = mmap(0, alloc_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);

	ASSERT (bs_ptr != MAP_FAILED);	
#endif
	ASSERT (bs_ptr);
	return bs_ptr;
}

extern struct s_victim_cache* mstore_get_tlb();

struct s_victim_cache* mstore_get_tlb_template()
{
	return gt_TLB;
}

// extern struct s_victim_cache* mstore_get_tlb();
extern int mstore_init(void* priv_data);
extern int mstore_cleanup();
extern uintptr_t mstore_get_mstorage_page(uintptr_t ptr);
extern uintptr_t mstore_get_mpage_cache_base_ptr();
extern void* mstore_alloc(size_t size, void* priv_data);
extern size_t mstore_get_mpage_size();
extern int mstore_get_mpage_bits();
extern void notify_tlb_cached(void* ptr);
extern void notify_tlb_dropped(void* ptr, bool dirty);
extern void* mpf_handler_c(void* ptr);
extern void mpf_handler_d(void* ptr, void* dst, size_t size);
extern void mstore_write_back(void* ptr, void* src, size_t size);

extern void mstore_open(char* filename, int fd, char always_register, char* registered);
extern void mstore_close(int fd);

extern ssize_t mstore_write(int fd, const void* buf, size_t count);
extern ssize_t mstore_read(int fd, void* buf, size_t count);

uintptr_t direct_mstore_get_mpage_cache_base_ptr()
{
	return 0;
}

uintptr_t direct_mstore_get_mstorage_page(uintptr_t ptr)
{
	g_debug("direct_mstore_get_mstorage_page not supported\n");
	abort();
	return 0;
}

void default_mstore_open(char* filename, int fd, char always_register, char* registered)
{
}

void default_mstore_close(int fd)
{
}

void* default_mstore_alloc(size_t size, void* priv_data)
{
	return nullptr;
}

ssize_t default_mstore_write(int fd, const void* buf, size_t count)
{
	return write(fd,buf,count);
}
ssize_t default_mstore_read(int fd, void* buf, size_t count)
{
	return read(fd,buf,count);
}

extern void* _0__cosmix_link(const void* ptr, int ptr_size, char is_vector_type, char dirty);
extern void* _1__cosmix_link(const void* ptr, int ptr_size, char is_vector_type, char dirty);
extern void* _2__cosmix_link(const void* ptr, int ptr_size, char is_vector_type, char dirty);
extern void* _3__cosmix_link(const void* ptr, int ptr_size, char is_vector_type, char dirty);
extern void  _0__cosmix_writeback_direct(const void* ptr, int ptr_size);
extern void  _1__cosmix_writeback_direct(const void* ptr, int ptr_size);
extern void  _2__cosmix_writeback_direct(const void* ptr, int ptr_size);
extern void  _3__cosmix_writeback_direct(const void* ptr, int ptr_size);

extern int32_t _0__cosmix_get_valid_iterations(const void* unlinked_ptr, const void* ptr, int64_t stepVal, int32_t ptrSize);
extern int32_t _1__cosmix_get_valid_iterations(const void* unlinked_ptr, const void* ptr, int64_t stepVal, int32_t ptrSize);
extern int32_t _2__cosmix_get_valid_iterations(const void* unlinked_ptr, const void* ptr, int64_t stepVal, int32_t ptrSize);
extern int32_t _3__cosmix_get_valid_iterations(const void* unlinked_ptr, const void* ptr, int64_t stepVal, int32_t ptrSize);

extern void _0_mstore_free(void* ptr);
extern void _1_mstore_free(void* ptr);
extern void _2_mstore_free(void* ptr);
extern void _3_mstore_free(void* ptr);
extern void* _0_mstore_alloc(size_t size, void* private_data);
extern size_t _0_mstore_alloc_size(void* ptr);
extern void* _1_mstore_alloc(size_t size, void* private_data);
extern size_t _1_mstore_alloc_size(void* ptr);
extern void* _2_mstore_alloc(size_t size, void* private_data);
extern size_t _2_mstore_alloc_size(void* ptr);
extern void* _3_mstore_alloc(size_t size, void* private_data);
extern size_t _3_mstore_alloc_size(void* ptr);

extern uintptr_t _0_mstore_get_mpage_cache_base_ptr();
extern size_t _0_mstore_get_mpage_size();
extern uintptr_t _1_mstore_get_mpage_cache_base_ptr();
extern size_t _1_mstore_get_mpage_size();
extern uintptr_t _2_mstore_get_mpage_cache_base_ptr();
extern size_t _2_mstore_get_mpage_size();
extern uintptr_t _3_mstore_get_mpage_cache_base_ptr();
extern size_t _3_mstore_get_mpage_size();

extern char _0_is_direct();
extern char _1_is_direct();
extern char _2_is_direct();
extern char _3_is_direct();

extern char mstore_is_direct();

char mstore_is_direct_true()
{
	return TRUE;
}

char mstore_is_direct_false()
{
	return FALSE;
}

char _10_is_direct()
{
	g_debug("Invalid usage");
	abort();
	return 0;
}

int32_t _10__cosmix_get_valid_iterations(const void* unlinked_ptr, const void* ptr, int64_t stepVal, int32_t ptrSize)
{
	g_debug("Invalid usage");
	abort();
	return 0;
}

void _10__cosmix_writeback_direct(const void* ptr, int ptr_size)
{
	// do nothing since if this is an invalid mstore we will catch it in the link method
	// if this is not a direct mstore we cannot abbort
}

void* _10__cosmix_link(const void* ptr, int ptr_size, char is_vector_type, char dirty)
{
	g_debug("Invalid usage");
	abort();

	return nullptr;
}

uintptr_t _10_mstore_get_mpage_cache_base_ptr()
{
	g_debug("Invalid usage");
	abort();

	return 0;
}

size_t _10_mstore_get_mpage_size()
{
	g_debug("Invalid usage");
	abort();

	return 0;

}

void _10_mstore_free(void* ptr)
{
	g_debug("Invalid usage");
	abort();

}

void* _10_mstore_alloc(size_t size, void* private_data)
{
	ASSERT("Invalid usage");
	abort();

	return nullptr;
}

size_t _10_mstore_alloc_size(void* ptr)
{
	g_debug("Invalid usage");
	abort();

	return 0;
}

// Template method for initializing mstores. Priv_data will be sent by the compiler based on the parsed config file when needed
//
int __cosmix_initialize_template(void* priv_data)
{
	// Note: the compiler will replace this called function with the correct mstore_init callback 
	//
	int res = mstore_init(priv_data);

	if (res)
	{
		g_debug("Failed initializing mstore, returned error is %d\n", res);
		abort();
	}

	if (!mstore_is_direct())
	{
		memset(gt_TLB, 0xFF, sizeof(struct s_victim_cache) * TLB_SIZE);
		gt_crosspage_access = 0;
		gt_crosspage_access_size = 0;
	}

	return res;
}

int __cosmix_cleanup_template()
{
	int res = mstore_cleanup();

	if (res)
	{
		g_debug("Failed releasing mstore resources, returned error is %d\n", res);
		abort();
	}

	return res;
}

extern size_t mstore_get_min_size();
extern size_t mstore_get_max_size();
extern uintptr_t mstore_tag(void* ptr);

size_t deafult_mstore_get_min_size()
{
	return 0;
}

size_t deafult_mstore_get_max_size()
{
	return 1000000000000;
}


uintptr_t mstore_tag_0(void* ptr)
{
	return MAKE_MSTORE0_PTR(ptr);
}

uintptr_t mstore_tag_1(void* ptr)
{
	return MAKE_MSTORE1_PTR(ptr);
}

uintptr_t mstore_tag_2(void* ptr)
{
	return MAKE_MSTORE2_PTR(ptr);
}

uintptr_t mstore_tag_3(void* ptr)
{
	return MAKE_MSTORE3_PTR(ptr);
}

void* __cosmix_malloc_template(size_t size) 
{	
	if ((size < mstore_get_min_size() || size >= mstore_get_max_size()))
	{
		return malloc(size);
	}

	void* bs_ptr = mstore_alloc(size, nullptr);
	void* masked_bs_ptr = (void*) mstore_tag(bs_ptr);

	return masked_bs_ptr;
}

void* __cosmix_calloc_template(size_t num_of_elements, size_t elements_size) {
	void* ptr = __cosmix_malloc_template(num_of_elements * elements_size);
	__cosmix_memset(ptr, 0, num_of_elements * elements_size);
	return ptr;
}

void* __attribute__((noinline)) __cosmix_mstore_annotation(void* ptr)
{
	return ptr;
} 

void* __cosmix_memalign_template(size_t alignment, size_t n) {	
	// Alignment is inherited in mstore page cache
	//
	void* bs_mem = mstore_alloc(n + (alignment-1) + sizeof(void*), nullptr);

    if(!bs_mem) {
    	return NULL;
    }

    char *bs_aligned_mem = ((char*)bs_mem) + sizeof(void*);
    bs_aligned_mem += (alignment - ((uintptr_t)bs_aligned_mem & (alignment - 1)) & (alignment-1));

    ((void**)bs_aligned_mem)[-1] = bs_mem;

    return (void*)mstore_tag(bs_aligned_mem);
}

/* Allocation & Deallocation Methods */
void __cosmix_free(void* p) {
	if (!IS_COSMIX_PTR(p))
	{
		free(p);
		return;
	}

	void* unmasked_bs_ptr = (void*) (uintptr_t)MAKE_ORIGINAL_POINTER(p);

	int topByte = (uintptr_t)p >> 60;
	
	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
			_0_mstore_free(unmasked_bs_ptr);
			break;
		case MSTORE1_SHIFT60_VAL:
			_1_mstore_free(unmasked_bs_ptr);
			break;
		case MSTORE2_SHIFT60_VAL:
			_2_mstore_free(unmasked_bs_ptr);
			break;
		case MSTORE3_SHIFT60_VAL:
			_3_mstore_free(unmasked_bs_ptr);
			break;
		default:
			abort();
	}
}

void* __cosmix_realloc(void* ptr, size_t size) {
	if (!IS_COSMIX_PTR(ptr)) {
		void* res = realloc(ptr,size);
		return res;
	}

	int orig_ptr_size = -1;
	void* res = nullptr;
	int topByte = (uintptr_t)ptr >> 60;
	void* unamsked_ptr = (void*)MAKE_ORIGINAL_POINTER(ptr);
	
	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
			orig_ptr_size = _0_mstore_alloc_size(unamsked_ptr);
			break;
		case MSTORE1_SHIFT60_VAL:
			orig_ptr_size = _1_mstore_alloc_size(unamsked_ptr);
			break;
		case MSTORE2_SHIFT60_VAL:
			orig_ptr_size = _2_mstore_alloc_size(unamsked_ptr);
			break;
		case MSTORE3_SHIFT60_VAL:
			orig_ptr_size = _3_mstore_alloc_size(unamsked_ptr);
			break;
		default:
			abort();
	}

	if (orig_ptr_size >= size) {
		return ptr; // just reuse the same memory
	}

	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
			res = (void*)MAKE_MSTORE0_PTR(_0_mstore_alloc(size, nullptr));
			break;
		case MSTORE1_SHIFT60_VAL:
			res = (void*)MAKE_MSTORE1_PTR(_1_mstore_alloc(size, nullptr));
			break;
		case MSTORE2_SHIFT60_VAL:
			res = (void*)MAKE_MSTORE2_PTR(_2_mstore_alloc(size, nullptr));
			break;
		case MSTORE3_SHIFT60_VAL:
			res = (void*)MAKE_MSTORE3_PTR(_3_mstore_alloc(size, nullptr));
			break;
		default:
			abort();
	}

	__cosmix_memcpy(res, ptr, orig_ptr_size);
	__cosmix_free(ptr);

	return res;
}

int32_t __cosmix_get_valid_iterations_template(const void* unlinked_ptr, const void* ptr, int64_t stepVal, int32_t ptrSize) 
{
	if (likely(!IS_COSMIX_PTR(unlinked_ptr))) 
	{
		// Return max val so native pointers will enjoy interuptless loops
		//
		return (1<<30); 
	}

	if (ptr == gt_CrossPageBuffer)
	{
		return 1;
	}

	int page_offset = (uintptr_t) ((uintptr_t)ptr - mstore_get_mpage_cache_base_ptr()) & (mstore_get_mpage_size() - 1);
	int realStep = stepVal;
	int left_bytes = (realStep > 0) ? (mstore_get_mpage_size() - page_offset) : -(page_offset+1);
	int32_t res = left_bytes / realStep;

	if (page_offset + ((res-1) * realStep) + ptrSize > mstore_get_mpage_size())
	{
		res--;
	}

	if (res <= 0)
	{
		return 1;
	}

	// TODO: theoretically we don't need MAKE_ORIGINAL_POINTER(ptr) but just ptr since its linked, but need to test this before removing
	//
	// ASSERT((((uintptr_t)(MAKE_ORIGINAL_POINTER(ptr) - mstore_get_mpage_cache_base_ptr()) & (mstore_get_mpage_size()-1)) + realStep * (res-1) + ptrSize) <= mstore_get_mpage_size());
	
	return res;
}

INLINEATTR void* __cosmix_link_cached_template(const void* ptr, int ptr_size, char is_vector_type, char dirty) 
{
	if (likely(!IS_COSMIX_PTR(ptr))) 
	{
		return (void*)ptr;
	}

	ASSERT(!is_vector_type);

	uintptr_t unmasked_bs_ptr = MAKE_ORIGINAL_POINTER(ptr);

	uintptr_t mstorage_page = mstore_get_mstorage_page(unmasked_bs_ptr);
	unsigned bs_page_index =  (mstorage_page >> mstore_get_mpage_bits());	
	unsigned page_offset= (mstorage_page & (mstore_get_mpage_size()-1));
	
#ifndef DISABLE_TLB
	struct s_victim_cache* tlb = mstore_get_tlb();

	int tlb_index=0;	

	do {
		if (tlb[tlb_index].bs_page_index == bs_page_index) {
			tlb[tlb_index].is_dirty |= dirty;
			uintptr_t res = mstore_get_mpage_cache_base_ptr() + tlb[tlb_index].epc_page_index * mstore_get_mpage_size() + page_offset;

			ASSERT((page_offset + ptr_size) <= mstore_get_mpage_size());
			
			return (void*)res;
		}
		tlb_index++;
	} while (tlb_index < TLB_SIZE);
#endif
	
	// TODO: res should be actually for EPC page but not with offset
	void* res = mpf_handler_c((void*)unmasked_bs_ptr);

#ifndef DISABLE_TLB
	// Decrease ref count since no one else in this thread is currently using this value
	// No need for lock because its per thread
	//
	int removed_page_index = tlb[TLB_SIZE-1].bs_page_index;
	if (removed_page_index >= 0)
	{
		void* removed_bs_page = (void*)(unmasked_bs_ptr - ((bs_page_index - removed_page_index) * mstore_get_mpage_size()));
		notify_tlb_dropped(removed_bs_page, tlb[TLB_SIZE-1].is_dirty);
	}

	// Now, add the new page to the TLB, in FIFO way
	memmove(&tlb[1], &tlb[0], sizeof(struct s_victim_cache) * (TLB_SIZE-1));

	notify_tlb_cached((void*)unmasked_bs_ptr);

	tlb[0].bs_page_index = bs_page_index;// (unmasked_bs_ptr - g_mstorage_base_ptr) >> COSMIX_PAGE_BITS;
	tlb[0].epc_page_index = ((uintptr_t)res - mstore_get_mpage_cache_base_ptr()) >> mstore_get_mpage_bits();
	tlb[0].is_dirty = dirty;

#endif

	ASSERT((((uintptr_t)((uintptr_t)res - mstore_get_mpage_cache_base_ptr()) & (mstore_get_mpage_size()-1)) + ptr_size) <= mstore_get_mpage_size());
	
	return res;
}

void* __cosmix_page_fault(const void* bs_ptr, char dirty) { 
	int topByte = (uintptr_t)bs_ptr >> 60;

	void* res = NULL;

	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
				res = _0__cosmix_link(bs_ptr, 0, 0, dirty);
				break;
		case MSTORE1_SHIFT60_VAL:
				res = _1__cosmix_link(bs_ptr, 0, 0, dirty);
				break;
		case MSTORE2_SHIFT60_VAL:
				res = _2__cosmix_link(bs_ptr, 0, 0, dirty);
				break;
		case MSTORE3_SHIFT60_VAL:
				res = _3__cosmix_link(bs_ptr, 0, 0, dirty);
				break;
		default:
				abort();
	}

	return res;
}

INLINEATTR void __cosmix_writeback_cached_cross_page_template()
{
	if (gt_crosspage_access != 0)
	{
		ASSERT(gt_crosspage_access_size != 0);

		uintptr_t bs_ptr = gt_crosspage_access;
		int size = gt_crosspage_access_size;
	
		// Reset for next cross page access
		//
		gt_crosspage_access = 0;
		gt_crosspage_access_size = 0;
	
		// writeback for old value
		//
		uintptr_t mstorage_page1 = mstore_get_mstorage_page(bs_ptr);
		unsigned page_offset1= (mstorage_page1 & (mstore_get_mpage_size()-1));
		unsigned bytes_to_copy_from_first_page = mstore_get_mpage_size() - page_offset1;
			
		void* first_page_ptr = __cosmix_page_fault((void*)bs_ptr, TRUE);
		void* second_page_ptr = __cosmix_page_fault((char*)bs_ptr + bytes_to_copy_from_first_page, TRUE);

		memcpy(first_page_ptr, gt_CrossPageBuffer, bytes_to_copy_from_first_page);
		memcpy(second_page_ptr, gt_CrossPageBuffer + bytes_to_copy_from_first_page, size - bytes_to_copy_from_first_page);
	}
}

void __cosmix_init_global_template(void* newGlobal, void* global, int size)
{
	// alloc
	//
	void* new_global_memory = (void*)mstore_tag(mstore_alloc(size, nullptr));
	
	// copy global data into mstore memory
	//
	__cosmix_memcpy(new_global_memory, global, size);

	// set newGlobal to point to the new global memory
	//
	*(void**)newGlobal = new_global_memory;	
}

INLINEATTR void* __cosmix_link_cached_cross_page_template(const void* ptr, int ptr_size, char is_vector_type, char dirty) 
{
	if (likely(!IS_COSMIX_PTR(ptr))) 
	{
		return (void*)ptr;
	}

	ASSERT(!is_vector_type);

	uintptr_t unmasked_bs_ptr = MAKE_ORIGINAL_POINTER(ptr);
	uintptr_t mstorage_page = mstore_get_mstorage_page(unmasked_bs_ptr);
	unsigned page_offset= (mstorage_page & (mstore_get_mpage_size()-1));

	if (page_offset + ptr_size > mstore_get_mpage_size())
	{
		// load from both pages into gt_CrossPageBuffer temp buffer
		//
		unsigned bytes_to_copy_from_first_page = mstore_get_mpage_size() - page_offset;
		void* first_page_ptr = __cosmix_page_fault(ptr, dirty);
		void* second_page_ptr = __cosmix_page_fault((char*)ptr + bytes_to_copy_from_first_page, dirty);

		memcpy(gt_CrossPageBuffer, first_page_ptr, bytes_to_copy_from_first_page);
		memcpy(gt_CrossPageBuffer + bytes_to_copy_from_first_page, second_page_ptr, ptr_size - bytes_to_copy_from_first_page);

		gt_crosspage_access = (uintptr_t)ptr;
		gt_crosspage_access_size = ptr_size;

		return gt_CrossPageBuffer;
	}

	unsigned bs_page_index =  (mstorage_page >> mstore_get_mpage_bits());	
	
#ifndef DISABLE_TLB
	struct s_victim_cache* tlb = mstore_get_tlb();

	int tlb_index=0;	

	do {
		if (tlb[tlb_index].bs_page_index == bs_page_index) {
			tlb[tlb_index].is_dirty |= dirty;
			uintptr_t res = mstore_get_mpage_cache_base_ptr() + tlb[tlb_index].epc_page_index * mstore_get_mpage_size() + page_offset;

			ASSERT((page_offset + ptr_size) <= mstore_get_mpage_size());

			return (void*)res;
		}
		tlb_index++;
	} while (tlb_index < TLB_SIZE);
#endif

	// TODO: res should be actually for EPC page but not with offset
	void* res = mpf_handler_c((void*)unmasked_bs_ptr);

#ifndef DISABLE_TLB
	// Decrease ref count since no one else in this thread is currently using this value
	// No need for lock because its per thread
	//
	int removed_page_index = tlb[TLB_SIZE-1].bs_page_index;
	if (removed_page_index >= 0)
	{
		void* removed_bs_page = (void*)(unmasked_bs_ptr - ((bs_page_index - removed_page_index) * mstore_get_mpage_size()));
		notify_tlb_dropped(removed_bs_page, tlb[TLB_SIZE-1].is_dirty);
	}

	// Now, add the new page to the TLB, in FIFO way
	memmove(&tlb[1], &tlb[0], sizeof(struct s_victim_cache) * (TLB_SIZE-1));

	notify_tlb_cached((void*)unmasked_bs_ptr);

	tlb[0].bs_page_index = bs_page_index;// (unmasked_bs_ptr - g_mstorage_base_ptr) >> COSMIX_PAGE_BITS;
	tlb[0].epc_page_index = ((uintptr_t)res - mstore_get_mpage_cache_base_ptr()) >> mstore_get_mpage_bits();
	tlb[0].is_dirty = dirty;

#endif

	ASSERT((((uintptr_t)((uintptr_t)res - mstore_get_mpage_cache_base_ptr()) & (mstore_get_mpage_size()-1)) + ptr_size) <= mstore_get_mpage_size());

	return res;
}

int32_t __cosmix_get_valid_iterations_generic(const void* unlinked_ptr, const void* ptr, int64_t stepVal, int32_t ptrSize) {
	if (likely(!IS_COSMIX_PTR(unlinked_ptr))) {
		// Return max val so native pointers will enjoy interuptless loops
		//
		return (1<<30); 
	}

	int topByte = (uintptr_t)unlinked_ptr >> 60;

	int32_t res;

	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
				res = _0__cosmix_get_valid_iterations(unlinked_ptr, ptr, stepVal, ptrSize);
				break;
		case MSTORE1_SHIFT60_VAL:
				res = _1__cosmix_get_valid_iterations(unlinked_ptr, ptr, stepVal, ptrSize);
				break;
		case MSTORE2_SHIFT60_VAL:
				res = _2__cosmix_get_valid_iterations(unlinked_ptr, ptr, stepVal, ptrSize);
				break;
		case MSTORE3_SHIFT60_VAL:
				res = _3__cosmix_get_valid_iterations(unlinked_ptr, ptr, stepVal, ptrSize);
				break;
		default:
				abort();
	}

	return res;
}

// Invokes mstore_write_back
//
INLINEATTR void __cosmix_writeback_direct_template(const void* ptr, int ptr_size)
{
	if (likely(!IS_COSMIX_PTR(ptr))) 
	{
		return;
	}

	void* unmasked_bs_ptr = (void*)MAKE_ORIGINAL_POINTER(ptr);

	int topByte = (uintptr_t)ptr >> 60;
	size_t mpage_size;

	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
			mpage_size = _0_mstore_get_mpage_size();
			break;
		case MSTORE1_SHIFT60_VAL:
			mpage_size = _1_mstore_get_mpage_size();
			break;
		case MSTORE2_SHIFT60_VAL:
			mpage_size = _2_mstore_get_mpage_size();
			break;
		case MSTORE3_SHIFT60_VAL:
			mpage_size = _3_mstore_get_mpage_size();
		default:
			abort();
	}

	void* dest = __cosmix_get_mstore_direct_buffer(mpage_size);

	// Note: internally, there might be multiple fetches from mstorage if the offset is between mpages
	//
	mstore_write_back(unmasked_bs_ptr, dest, ptr_size);	
}

void __cosmix_writeback_generic(const void* ptr, int ptr_size)
{
	if (likely(!IS_COSMIX_PTR(ptr))) 
	{
		return;
	}

	int topByte = (uintptr_t)ptr >> 60;

	switch (topByte) 
	{
		case MSTORE0_SHIFT60_VAL:
			_0__cosmix_writeback_direct(ptr, ptr_size);
			break;
		case MSTORE1_SHIFT60_VAL:
			_1__cosmix_writeback_direct(ptr, ptr_size);
			break;
		case MSTORE2_SHIFT60_VAL:
			_2__cosmix_writeback_direct(ptr, ptr_size);
			break;
		case MSTORE3_SHIFT60_VAL:
			_3__cosmix_writeback_direct(ptr, ptr_size);
			break;
		default:
			abort();
	}
}

INLINEATTR void* __cosmix_link_direct_template(const void* ptr, int ptr_size, char is_vector_type, char dirty) 
{
	if (likely(!IS_COSMIX_PTR(ptr))) 
	{
		return (void*)ptr;
	}

	void* unmasked_bs_ptr = (void*)MAKE_ORIGINAL_POINTER(ptr);

	int topByte = (uintptr_t)ptr >> 60;
	size_t mpage_size;

	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
			mpage_size = _0_mstore_get_mpage_size();
			break;
		case MSTORE1_SHIFT60_VAL:
			mpage_size = _1_mstore_get_mpage_size();
			break;
		case MSTORE2_SHIFT60_VAL:
			mpage_size = _2_mstore_get_mpage_size();
			break;
		case MSTORE3_SHIFT60_VAL:
			mpage_size = _3_mstore_get_mpage_size();
		default:
			abort();
	}

	// Note: for now, just assert it, otherwise should divide to two separate requests
	//
	ASSERT(mpage_size >= ptr_size);

	void* dest = __cosmix_get_mstore_direct_buffer(mpage_size);

	// Note: internally, there might be multiple fetches from mstorage if the offset is between mpages
	//
	mpf_handler_d(unmasked_bs_ptr, dest, ptr_size);

	return dest;
}

void* __cosmix_link_generic(const void* ptr, int ptr_size, char is_vector_type, char dirty) 
{
	if (likely(!IS_COSMIX_PTR(ptr))) {
		return (void*)ptr;
	}

	int topByte = (uintptr_t)ptr >> 60;

	void* res = NULL;

	switch (topByte) 
	{
		case MSTORE0_SHIFT60_VAL:
			res = _0__cosmix_link(ptr, ptr_size, is_vector_type, dirty);
			break;
		case MSTORE1_SHIFT60_VAL:
			res = _1__cosmix_link(ptr, ptr_size, is_vector_type, dirty);
			break;
		case MSTORE2_SHIFT60_VAL:
			res = _2__cosmix_link(ptr, ptr_size, is_vector_type, dirty);
			break;
		case MSTORE3_SHIFT60_VAL:
			res = _3__cosmix_link(ptr, ptr_size, is_vector_type, dirty);
			break;
		default:
			abort();
	}

	return res;
}

/* MemIntrinsic functions */

// Mem intrinsics managements wrapper functions

char mstore_type_is_direct(void* ptr)
{
	int topByte = (uintptr_t)ptr >> 60;

	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
			return _0_is_direct();
		case MSTORE1_SHIFT60_VAL:
			return _1_is_direct();
		case MSTORE2_SHIFT60_VAL: 
			return _2_is_direct();
		case MSTORE3_SHIFT60_VAL:
			return _3_is_direct();
		default:
			abort();
	}

	return FALSE;
}

void get_mstore_parameters(void* ptr, uintptr_t* base_addr, size_t* block_size)
{
	int topByte = (uintptr_t)ptr >> 60;
	
	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
			// Note: we replace these calls with the correct mstore value. The compiler will take all these and call correct mstore callback
			*base_addr = _0_mstore_get_mpage_cache_base_ptr();
			*block_size = _0_mstore_get_mpage_size();
			break;
		case MSTORE1_SHIFT60_VAL:
			*base_addr = _1_mstore_get_mpage_cache_base_ptr();
			*block_size = _1_mstore_get_mpage_size();
			break;
		case MSTORE2_SHIFT60_VAL:
			*base_addr = _2_mstore_get_mpage_cache_base_ptr();
			*block_size = _2_mstore_get_mpage_size();
			break;
		case MSTORE3_SHIFT60_VAL:
			*base_addr = _3_mstore_get_mpage_cache_base_ptr(); 
			*block_size = _3_mstore_get_mpage_size();
		default:
			abort();
	}
}

int __cosmix_mem_wrapper(void *vl, char vl_dirty, void *vr, char vr_dirty, size_t n, t_mem_function func, char partial_return) 
{
	int vl_linked = IS_COSMIX_PTR(vl);
	int vr_linked = IS_COSMIX_PTR(vr);

	if (likely(!vl_linked && !vr_linked)) 
	{
		return (*func)(vl,vr,n);
	}

	// TODO: if direct, then should only use writeback if vl dirty, and page_fault if vr dirty
	//
	char is_mstore_direct = vl_linked ? mstore_type_is_direct(vl) : mstore_type_is_direct(vr);
	if (is_mstore_direct)
	{
		// TODO: add support to multiple variable direct mstores
		//
		ASSERT(!(vl_linked && vr_linked));
	}

	uintptr_t vl_base_addr;
	uintptr_t vr_base_addr;
	size_t vl_block_size;
	size_t vr_block_size;

	if (vl_linked)
	{
		get_mstore_parameters(vl, &vl_base_addr, &vl_block_size);
	}

	if (vr_linked)
	{
		get_mstore_parameters(vr, &vr_base_addr, &vr_block_size);
	}

	int ctr = n;
	unsigned char* vl0 = vl_linked ? (unsigned char*)__cosmix_page_fault(vl, vl_dirty) : (unsigned char*)vl;
	unsigned char* vr0 = vr_linked ? (unsigned char*)__cosmix_page_fault(vr, vr_dirty) : (unsigned char*)vr;
	unsigned char* vl1 = (unsigned char*)vl;
	unsigned char* vr1 = (unsigned char*)vr;

	unsigned vl_block_offset_mask = (vl_block_size -1);
	unsigned vr_block_offset_mask = (vr_block_size -1);

	while (ctr > 0) {
		int vr_page_offset = (uintptr_t)(vr0 - vr_base_addr) & vr_block_offset_mask;
		int vl_page_offset = (uintptr_t)(vl0 - vl_base_addr) & vl_block_offset_mask;		
		int left_in_vr = vr_linked ? (vr_block_size - vr_page_offset) : (1<< 30);
		int left_in_vl = vl_linked ? (vl_block_size - vl_page_offset) : (1<< 30);
		int min_left = left_in_vr < left_in_vl ? left_in_vr : left_in_vl;

		if (ctr > min_left) {
			int res = (*func)((void*)vl0, (void*)vr0, min_left);

			if (is_mstore_direct)
			{
				if (vl_linked && vl_dirty)
				{
					__cosmix_writeback_generic(vl1, vl_block_size);
				}

				if (vr_linked && vr_dirty)
				{
					__cosmix_writeback_generic(vr1, vr_block_size);
					//__cosmix_write_page(vr1);
				}
			}

			if (partial_return && res != 0)
			{
				return res;
			}			

			vl1 += min_left;
			vr1 += min_left;

			if (min_left == left_in_vl && vl_linked)
			{				
				vl0 = (unsigned char*)__cosmix_page_fault(vl1, vl_dirty);
			}
			else
			{
				vl0 += min_left;
			}

			if (min_left == left_in_vr && vr_linked) 
			{
				vr0 = (unsigned char*)__cosmix_page_fault(vr1, vr_dirty);
			}
			else
			{
				vr0 += min_left;
			}

			ctr -= min_left;
		} else {
			int res = (*func)((void*)vl0, (void*)vr0, ctr);

			if (is_mstore_direct)
			{
				if (vl_linked && vl_dirty)
				{
					__cosmix_writeback_generic(vl1, vl_block_size);
				}

				if (vr_linked && vr_dirty)
				{
					__cosmix_writeback_generic(vr1, vr_block_size);
					//__cosmix_write_page(vr1);
				}
			}

			if (partial_return && res != 0)
			{
				return res;
			}

			ctr -= ctr;
		}
	}

	return 0;
}

uintptr_t __cosmix_mem_wrapper_single(void* dest, int c, size_t n, t_mem_function_single func, char dirty, char partial_return, char aggregate_res) {
	if (likely(!IS_COSMIX_PTR(dest)))
	{
		return (*func)(dest, c, n);
	}

	int topByte = (uintptr_t)dest >> 60;
	size_t acc = 0;
	
	uintptr_t base_addr;
	size_t block_size;
	char is_mstore_direct = mstore_type_is_direct(dest);

	get_mstore_parameters(dest, &base_addr, &block_size);

	unsigned block_offset_mask = (block_size -1);

	int ctr = n;
	unsigned char* dst_orig = (unsigned char*)dest;
	unsigned char* dst0 = (unsigned char*)__cosmix_page_fault(dest, dirty);

	while (ctr > 0) {
		int dest_offset = (uintptr_t)(dst0 - base_addr) & block_offset_mask;
		int left_in_dest = block_size - dest_offset;

		if (ctr > left_in_dest) {
			uintptr_t res = (*func)((void*)dst0, c, left_in_dest);

			if (is_mstore_direct)
			{
				// __cosmix_write_page(dst_orig);
				__cosmix_writeback_generic(dst_orig, block_size);
			}

			if (partial_return && res != 0)
			{
				return res;
			}

			if (aggregate_res)
			{
				acc += (size_t)res;
			}

			dst_orig += left_in_dest;
			dst0 = (unsigned char*)__cosmix_page_fault(dst_orig, dirty);

			ctr -= left_in_dest;
		} else {
			uintptr_t res = (*func)((void*)dst0, c, ctr);

			if (is_mstore_direct)
			{
				// __cosmix_write_page(dst_orig);
				__cosmix_writeback_generic(dst_orig, block_size);
			}

			if (partial_return && res != 0)
			{
				return res;
			}
			
			if (aggregate_res)
			{
				acc += (size_t)res;
			}

			ctr -= ctr;
		}
	}

	if (aggregate_res)
	{
		return (uintptr_t)acc;
	}

	return 0;
}

int __cosmix_memmove_wrapper(void* dst, void* src, size_t n)
{
	memmove(dst, (const void*)src, n);
	return 0;
}

int __cosmix_memcpy_wrapper(void* dst, void* src, size_t n)
{
	memcpy(dst, (const void*)src, n);
	return 0;
}

int __cosmix_memcmp_wrapper(void* dst, void* src, size_t n)
{
	return memcmp((const void*)dst, (const void*)src, n);
}

uintptr_t __cosmix_memchr_wrapper(void* dst, int c, size_t n)
{
	return (uintptr_t)memchr((const void*)dst, c, n);
}

uintptr_t __cosmix_memset_wrapper(void* dst, int c, size_t n)
{
	return (uintptr_t)memset(dst, c, n);
}

void* __cosmix_memmove(void *dest, const void *src, size_t n) 
{
	__cosmix_mem_wrapper((void*)dest, TRUE, (void*)src, FALSE, n, &__cosmix_memmove_wrapper, FALSE);

	return dest;
}

void* __cosmix_memcpy(void *__restrict__ dest, const void *__restrict__ src, size_t n) 
{
	__cosmix_mem_wrapper((void*)dest, TRUE, (void*)src, FALSE, n, &__cosmix_memcpy_wrapper, FALSE);

	return dest;
}

int __cosmix_memcmp(const void *vl, const void *vr, size_t n) 
{
	int res = __cosmix_mem_wrapper((void*)vl, FALSE, (void*)vr, FALSE, n, &__cosmix_memcmp_wrapper, TRUE);

	return res;
}	

void* __cosmix_memchr(const void *dest, int c, size_t n) 
{	
	uintptr_t res = __cosmix_mem_wrapper_single((void*)dest, c, n, &__cosmix_memchr_wrapper, FALSE, TRUE, FALSE);
	
	return (void*)res;
}

void* __cosmix_memset(void *dest, int c, size_t n) 
{
	__cosmix_mem_wrapper_single(dest, c, n, &__cosmix_memset_wrapper, TRUE, FALSE, FALSE);

	return dest;
}

/*
 * General purpose LibC cosmix proxy methods
*/

// String manipulations

size_t __cosmix_strlen(const char *s) {
	int s_linked = IS_COSMIX_PTR(s);

	if (likely(!s_linked)) {
		return strlen(s);
	}

	// int topByte = (uintptr_t)s >> 60;
	
	uintptr_t base_addr;
	size_t block_size;

	get_mstore_parameters((void*)s, &base_addr, &block_size);

	unsigned block_offset_mask = (block_size -1);

	size_t res = 0;
	unsigned char* s0 = (unsigned char*)__cosmix_page_fault(s, 0);
	unsigned char* s1 = (unsigned char*)s;

	while (1) {
		size_t dest_offset = (uintptr_t)(s0 - base_addr) & block_offset_mask;
		size_t left_in_dest = block_size - dest_offset;

		size_t curr_res = strnlen((const char*)s0, left_in_dest);

		if (curr_res < left_in_dest) { // found a '\0' char			
			return res + curr_res;
		}
		
		s1 += left_in_dest;
		s0 = (unsigned char*)__cosmix_page_fault(s1, 0);
		res += left_in_dest;
	}	

	// unreachable
	abort();
}

char* __cosmix_strchr(const char *s , int c) {
	if (!IS_COSMIX_PTR(s)) {
		return (char*)strchr(s, c);
	}

	// Simple code reuse: inefficient implementation
	size_t len = __cosmix_strlen(s);
	void* res = __cosmix_memchr(s, c, len);

	return (char*)res;
}

int __cosmix_strcmp(const char *s1, const char *s2)
{
	int is_s1_cosmix = IS_COSMIX_PTR(s1);
	int is_s2_cosmix = IS_COSMIX_PTR(s2);

	if (!is_s1_cosmix && !is_s2_cosmix) {
		return strcmp(s1,s2);
	}

	uintptr_t s1_base_addr;
	uintptr_t s2_base_addr;
	size_t s1_block_size;
	size_t s2_block_size;

	// int topByte = is_s1_cosmix ? (uintptr_t)s1 >> 60 : (uintptr_t)s2 >> 60; 
	if (is_s1_cosmix)
	{
		get_mstore_parameters((void*)s1, &s1_base_addr, &s1_block_size);
	}

	if (is_s2_cosmix)
	{
		get_mstore_parameters((void*)s2, &s2_base_addr, &s2_block_size);
	}

	unsigned s1_block_offset_mask = (s1_block_size -1);	
	unsigned s2_block_offset_mask = (s2_block_size -1);	

	unsigned char* s10 = is_s1_cosmix ? (unsigned char*)__cosmix_page_fault(s1, FALSE) : (unsigned char*)s1;
	unsigned char* s20 = is_s2_cosmix ? (unsigned char*)__cosmix_page_fault(s2, FALSE) : (unsigned char*)s2;
	int s1_offset = (uintptr_t)(s10 - s1_base_addr) & s1_block_offset_mask;
	int s2_offset = (uintptr_t)(s20 - s2_base_addr) & s2_block_offset_mask;
	int left_in_s1 = is_s1_cosmix ? (s1_block_size - s1_offset) : (1<< 30);
	int left_in_s2 = is_s2_cosmix ? (s2_block_size - s2_offset) : (1<< 30);
	int min_left = left_in_s1 < left_in_s2 ? left_in_s1 : left_in_s2;

	while (TRUE)
	{
		int i=0;
		for (; i < min_left && *s10==*s20 && *s10; s10++, s20++,i++);

		if (i<min_left)
		{
			return *(unsigned char *)s10 - *(unsigned char *)s20;
		}
		
		if (i==left_in_s1)
		{
			s10 = (unsigned char*)__cosmix_page_fault((unsigned char*)s1+i, FALSE);
			left_in_s1 = s1_block_size;
		}

		if (i==left_in_s2)
		{
			s20 = (unsigned char*)__cosmix_page_fault((unsigned char*)s2+i, FALSE);
			left_in_s2 = s2_block_size;
		}

		i=0;
		min_left = left_in_s1 < left_in_s2 ? left_in_s1 : left_in_s2;
	}
}

int __cosmix_strncmp(const char *s1, const char *s2, size_t n) {
	int is_s1_cosmix = IS_COSMIX_PTR(s1);
	int is_s2_cosmix = IS_COSMIX_PTR(s2);

	if (!is_s1_cosmix && !is_s2_cosmix) {
		return strncmp(s1,s2,n);
	}

	size_t s1_len = __cosmix_strlen(s1);
	size_t s2_len = __cosmix_strlen(s2);

	char* native_ptr1 = (char*)s1;
	char* native_ptr2 = (char*)s2;

	if (is_s1_cosmix)
	{
		native_ptr1 = (char*)malloc(s1_len+1);
		__cosmix_memcpy(native_ptr1, s1, s1_len);
		native_ptr1[s1_len] = '\0';
	}

	if (is_s2_cosmix)
	{
		native_ptr2 = (char*)malloc(s2_len+1);
		__cosmix_memcpy(native_ptr2, s2, s2_len);
		native_ptr2[s2_len] = '\0';
	}

	int res = strncmp(native_ptr1, native_ptr2, n);

	if (is_s1_cosmix)
	{
		free(native_ptr1);
	}
	
	if (is_s2_cosmix)
	{
		free(native_ptr2);
	}

	return res;
}

/*
 * Non-C99
 */

int __cosmix_strncasecmp(const char *s1, const char *s2, size_t n) {
	int is_s1_cosmix = IS_COSMIX_PTR(s1);
	int is_s2_cosmix = IS_COSMIX_PTR(s2);

	if (!is_s1_cosmix && !is_s2_cosmix) {
		return strncasecmp(s1,s2,n);
	}

	size_t s1_len = __cosmix_strlen(s1);
	size_t s2_len = __cosmix_strlen(s2);

	char* native_ptr1 = (char*)s1;
	char* native_ptr2 = (char*)s2;

	if (is_s1_cosmix)
	{
		native_ptr1 = (char*)malloc(s1_len+1);
		__cosmix_memcpy(native_ptr1, s1, s1_len);
		native_ptr1[s1_len] = '\0';
	}

	if (is_s2_cosmix)
	{
		native_ptr2 = (char*)malloc(s2_len+1);
		__cosmix_memcpy(native_ptr2, s2, s2_len);
		native_ptr2[s2_len] = '\0';
	}

	int res = strncasecmp(native_ptr1, native_ptr2, n);

	if (is_s1_cosmix)
	{
		free(native_ptr1);
	}
	
	if (is_s2_cosmix)
	{
		free(native_ptr2);
	}

	return res;
}

int __cosmix_strcasecmp(const char *s1, const char *s2) {
	int is_s1_cosmix = IS_COSMIX_PTR(s1);
	int is_s2_cosmix = IS_COSMIX_PTR(s2);

	if (!is_s1_cosmix && !is_s2_cosmix) {
		return strcasecmp(s1,s2);
	}
	
	size_t s1_len = __cosmix_strlen(s1);
	size_t s2_len = __cosmix_strlen(s2);

	char* native_ptr1 = (char*)s1;
	char* native_ptr2 = (char*)s2;

	if (is_s1_cosmix)
	{
		native_ptr1 = (char*)malloc(s1_len+1);
		__cosmix_memcpy(native_ptr1, s1, s1_len);
		native_ptr1[s1_len] = '\0';
	}

	if (is_s2_cosmix)
	{
		native_ptr2 = (char*)malloc(s2_len+1);
		__cosmix_memcpy(native_ptr2, s2, s2_len);
		native_ptr2[s2_len] = '\0';
	}

	int res = strcasecmp(native_ptr1, native_ptr2);

	if (is_s1_cosmix)
	{
		free(native_ptr1);
	}
	
	if (is_s2_cosmix)
	{
		free(native_ptr2);
	}

	return res;
}

/* NON SGX SDK LibC proxy methods below */

#ifndef SDK_BUILD

ssize_t __cosmix_sendmsg(int fd, const struct msghdr *msg, int flags) {
    ASSERT (!IS_COSMIX_PTR(msg));
    ASSERT (!IS_COSMIX_PTR(msg->msg_name));
    ASSERT (!IS_COSMIX_PTR(msg->msg_control));
    ASSERT (!IS_COSMIX_PTR(msg->msg_iov));

    int i;
    struct msghdr msgval;
	msgval.msg_name = NULL;
	msgval.msg_namelen = 0;
	msgval.msg_iov = NULL;
	msgval.msg_iovlen = 0;
	msgval.msg_control = NULL;
	msgval.msg_controllen = 0;
	msgval.msg_flags = 0;
	//  = {.msg_name = NULL, .msg_namelen = 0, .msg_iov = NULL, .msg_iovlen = 0, .msg_control = NULL, .msg_controllen =     0, .msg_flags = 0};

    if (msg->msg_name) {
    	msgval.msg_name = msg->msg_name;
    }
   
    if (msg->msg_control) {
    	msgval.msg_control = msg->msg_control;
    }

    msgval.msg_namelen = msg->msg_namelen;
    msgval.msg_controllen  = msg->msg_controllen;
    msgval.msg_flags   = msg->msg_flags;

	// TODO: can use cached thread value and save redundant mallocs
    struct iovec* iovval = (struct iovec*)malloc(msg->msg_iovlen * 2 * sizeof(struct iovec));
    struct iovec *msgiov = msg->msg_iov;

    // first get number of new msgs. These are the ones that are if "valid" block size
    int iovlen = 0;
    int index=0;
    for (i = 0; i < msg->msg_iovlen; i++) 
	{
		if (!IS_COSMIX_PTR(msgiov[i].iov_base)) 
		{
			iovval[index].iov_base = msgiov[i].iov_base;
			iovval[index].iov_len = msgiov[i].iov_len;
			index++;
			iovlen++;
			continue;
		}

		// int topByte = (uintptr_t)msgiov[i].iov_base >> 60;
		uintptr_t base_addr;
		size_t block_size;

		char is_mstore_direct = mstore_type_is_direct(msgiov[i].iov_base);

		get_mstore_parameters(msgiov[i].iov_base, &base_addr, &block_size);

		unsigned block_offset_mask = (block_size -1);

		int ctr = msgiov[i].iov_len;	
		unsigned char* dst = (unsigned char*)__cosmix_page_fault(msgiov[i].iov_base, 0);
		unsigned char* dst_orig = (unsigned char*)msgiov[i].iov_base;

		while (ctr > 0) 
		{
			int block_offset = (uintptr_t)(dst - base_addr) & block_offset_mask;
			int left = block_size - block_offset;

			if (ctr > left) 
			{
				iovval[index].iov_base = dst;
				iovval[index].iov_len = left;
				iovlen++;
				index++;

				if (is_mstore_direct)
				{
					__cosmix_writeback_generic(dst_orig, block_size);
				}

				ctr -= left;
				//dst = unlink_ptr((uintptr_t)dst, DIFF_PAGE(dst,msgiov[i].iov_base));
				dst_orig += ctr;
				dst = (unsigned char*)__cosmix_page_fault(dst_orig, 0);		
			}
			else 
			{
				if (is_mstore_direct)
				{
					__cosmix_writeback_generic(dst_orig, block_size);
				}

				iovval[index].iov_base = dst;
				iovval[index].iov_len = ctr;
				index++;
				iovlen++;

				//unlink_ptr((uintptr_t)dst, DIFF_PAGE(dst,msgiov[i].iov_base));
				ctr = 0;
			}
		}
    }

    msgval.msg_iov = iovval;
    msgval.msg_iovlen  = iovlen;
    ASSERT (iovlen <= msg->msg_iovlen * 2);

    ssize_t ret = sendmsg(fd, &msgval, flags);

    // Finally, free the resources
    free(iovval);

    return ret;
}

uintptr_t __cosmix_read_wrapper(void* buf, int fd, size_t count)
{
	ssize_t res = read(fd, buf, count);

	return (uintptr_t)res;
}

uintptr_t __cosmix_write_wrapper(void* buf, int fd, size_t count)
{	
	ssize_t res = g_storage_used ? mstore_write(fd, buf, count) : write(fd, buf, count);

	return (uintptr_t)res;
}

static __thread off_t gt_curr_pwrite_offset;
static __thread off_t gt_curr_pread_offset;

uintptr_t __cosmix_pwrite_wrapper(void* buf, int fd, size_t count)
{
	ssize_t res = pwrite(fd, buf, count, gt_curr_pwrite_offset);

	gt_curr_pwrite_offset += count;

	return (uintptr_t)res;
}

uintptr_t __cosmix_pread_wrapper(void* buf, int fd, size_t count)
{
	ssize_t res = pread(fd, buf, count, gt_curr_pread_offset);

	gt_curr_pread_offset += count;

	return (uintptr_t)res;
}

int __cosmix_open(const char *filename, int flags, ...) 
{
	char* native_ptr = (char*)filename;
	if (IS_COSMIX_PTR(filename))
	{
		size_t len = __cosmix_strlen(filename);
		native_ptr = (char*)malloc(len+1);
		__cosmix_memcpy(native_ptr, filename, len);
		native_ptr[len] = '\0';
	}

	int res;

	mode_t mode = 0;
	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) 
	{
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
		res = open(native_ptr, flags, mode);
	}
	else
	{
		res = open(native_ptr, flags);
	}

	if (IS_COSMIX_PTR(filename))
	{
		free(native_ptr);
	}

	// The opened fd should be registered with the storage mstore
#ifdef COSMIX_MMAP_ALL_FILES
	char register_fd = TRUE;
#else
	char register_fd = FALSE;
#endif

	char registered = FALSE;

	if (res > 0)
	{
		// store in runtime list
		mstore_open((char*)filename, res, register_fd, &registered);
		
		if (registered)
		{
			g_storage_used = TRUE;
		}
	}

	return res;
}

int __cosmix_open64(const char *filename, int flags, ...)
{
	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) 
	{
		va_list ap;
		va_start(ap, flags);
		mode_t mode = va_arg(ap, mode_t);
		va_end(ap);
		return __cosmix_open(filename, flags, mode);
	}

	return __cosmix_open(filename, flags);
}

int __cosmix_close(int fd)
{
	int res = close(fd);

	if (res)
	{
		mstore_close(fd);
	}

	return res;
}

ssize_t __cosmix_read(int fd, void *buf, size_t count) {
	if (likely(!IS_COSMIX_PTR(buf))) 
	{
		if (likely(!g_storage_used))
		{
			return read(fd, buf, count);
		}

		return mstore_read(fd, buf, count);
	}

	void* native_ptr = malloc(count);
	ssize_t res = g_storage_used ? mstore_read(fd, native_ptr, count) : read(fd, native_ptr, count);
	
	if (res > 0)
	{
		__cosmix_memcpy(buf, native_ptr, res);
	}

	free(native_ptr);
	return res;

//	uintptr_t res = __cosmix_mem_wrapper_single(buf, fd, count, &__cosmix_read_wrapper, TRUE, FALSE, TRUE);
//	return (ssize_t)res;
}

ssize_t __cosmix_pread(int fd, void *buf, size_t size, off_t ofs) {
    if (likely(!IS_COSMIX_PTR(buf))) 
	{
    	return pread(fd, buf, size, ofs);
    }

	gt_curr_pread_offset = ofs;
	uintptr_t res = __cosmix_mem_wrapper_single((void*)buf, fd, size, &__cosmix_pread_wrapper, TRUE, FALSE, TRUE);
	
	return (ssize_t)res;
}

ssize_t __cosmix_pread64(int fd, void *buf, size_t size, off_t ofs) {
    return __cosmix_pread(fd, buf, size, ofs);
}

ssize_t __cosmix_pwrite(int fd, const void *buf, size_t size, off_t ofs) {
	if (likely(!IS_COSMIX_PTR(buf))) 
	{
    	return pwrite(fd, buf, size, ofs);
    }

	gt_curr_pwrite_offset = ofs;
	uintptr_t res = __cosmix_mem_wrapper_single((void*)buf, fd, size, &__cosmix_pwrite_wrapper, FALSE, FALSE, TRUE);
	
	return (ssize_t)res;
}

ssize_t __cosmix_pwrite64(int fd, const void *buf, size_t size, off_t ofs) {
		return __cosmix_pwrite(fd, buf, size, ofs);
}

ssize_t __cosmix_write(int fd, const void *buf, size_t count) {
	if (likely(!IS_COSMIX_PTR(buf))) 
	{
		if (likely(!g_storage_used))
		{
			return write(fd, buf, count);
		}

		// TODO: only if fd is part of the runtime list for the mstore
		//
		return mstore_write(fd, buf, count);
	}

	uintptr_t res = __cosmix_mem_wrapper_single((void*)buf, fd, count, &__cosmix_write_wrapper, FALSE, FALSE, TRUE);

	return (ssize_t)res;
}

void __cosmix_qsort(void *base, size_t nel, size_t width, int (*compar)(const void*,const void*)) {
	if (!IS_COSMIX_PTR(base)) 
	{
		return qsort(base, nel, width, compar);
	}

	void* native_ptr = malloc(nel*width);	
	__cosmix_memcpy(native_ptr, base, nel*width);
	qsort(native_ptr, nel, width, compar);
	__cosmix_memcpy(base, native_ptr, nel*width);

	free(native_ptr);
}

char __cosmix_is_reg_file(int fd)
{
	if (fd < 0)
	{
		return FALSE;
	}

	struct stat _stat;
	fstat(fd, &_stat);
	return S_ISREG(_stat.st_mode);
}

void* __cosmix_mmap_template(void *start, size_t len, int prot, int flags, int fd, off_t off) {
	// For now just support file-backed mstores for mmap calls
	//
	if (!__cosmix_is_reg_file(fd))
	{
		return mmap(start, len, prot, flags, fd, off);
	}

	struct s_file_alloc_privdata priv_data;
	priv_data.fd = fd;
	priv_data.prot = prot;
	priv_data.flags = flags;
	priv_data.off = off;
	priv_data.start = start;
	priv_data.alloc_succeeded = FALSE;

	// Until shmem fault handler is available - always use MAP_PRIVATE scheme
	//
	void* ptr = mstore_alloc(len, (void*)&priv_data);

	if (priv_data.alloc_succeeded)
	{
		void* res = (void*)mstore_tag(ptr);
		return res;

	}

	return mmap(start, len, prot, flags, fd, off);
}

// void* __cosmix_mmap64_template(void *start, size_t len, int prot, int flags, int fd, off_t off) {
// 	// Use same implementation as mmap
// 	//
//     return __cosmix_mmap_template(start, len, prot, flags, fd, off);
// }

int __cosmix_munmap(void *start, size_t len) 
{
	if (!IS_COSMIX_PTR(start))
	{
		return munmap(start, len);
	}

	void* unmasked_bs_ptr = (void*) (uintptr_t)MAKE_ORIGINAL_POINTER(start);

	int topByte = (uintptr_t)start >> 60;
	
	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
			_0_mstore_free(unmasked_bs_ptr);
			break;
		case MSTORE1_SHIFT60_VAL:
			_1_mstore_free(unmasked_bs_ptr);
			break;
		case MSTORE2_SHIFT60_VAL:
			_2_mstore_free(unmasked_bs_ptr);
			break;
		case MSTORE3_SHIFT60_VAL:
			_3_mstore_free(unmasked_bs_ptr);
			break;
		default:
			abort();
	}

	return 0;
}

int __cosmix_munmap64(void *start, size_t len) {
	// Use same munmap implementation
	//
    return __cosmix_munmap(start, len);
}


void* __cosmix_mremap(void *old_addr, size_t old_len, size_t new_len, int flags, ...) {
	if (!IS_COSMIX_PTR(old_addr))
	{
		va_list ap;
		va_start(ap, flags);
		void* res = mremap(old_addr, old_len, new_len, flags, ap);
		va_end(ap);

		return res;
	}

	// Note: since we just need to change the mapping internally
	// storage_mremap(old_addr, new_len, flags);

	return old_addr;
}

int __cosmix_mprotect(void *addr, size_t len, int prot) {
	// Note: until SGX2 no support for change in protection bits
	if (!IS_COSMIX_PTR(addr))
	{
	    return mprotect(addr, len, prot);
	}

	UNSUPPORTED_FUNC();
}

int __cosmix_madvise(void *addr, size_t len, int advice) {
	// COSMIX doens't yet consider madvise - we plan to introduce smart prefetching 
	// according to values passed here. For now, enjoy the advised info for the backing store
	if (!IS_COSMIX_PTR(addr))
	{
		return madvise(addr, len, advice);
	}

	// otherwise do nothing
	return 0;
}

int __cosmix_mincore(void *addr, size_t len, unsigned char *vec) {
	if (!IS_COSMIX_PTR(addr))
	{
    	return mincore(addr, len, vec);
	}

	// TODO: check if there is a mapping in the page cache
	UNSUPPORTED_FUNC();
}

int __cosmix_access(const char *filename, int amode) 
{
	if (!IS_COSMIX_PTR(filename))
	{
		return access(filename, amode);
	}

	UNSUPPORTED_FUNC();
}

char* __cosmix_getcwd(char *buf, size_t size)
{
	char tmp[PATH_MAX];
	char* ret = getcwd(tmp, size);
	
	if (IS_COSMIX_PTR(buf))
	{
		__cosmix_memcpy(buf, tmp, size);
	}
	else 
	{
		if (buf)
		{
			memcpy(buf, tmp, size);		
		}
		else
		{
			return strdup(tmp);
		}
	}

	return ret;
}

int __cosmix_fstat(int fd, struct stat *st) {
	if (!IS_COSMIX_PTR(st))
	{
		return fstat(fd, st);
	}

	// should actually allocate native and memcpy
	//
	UNSUPPORTED_FUNC();
}

int __cosmix_fstat64(int fd, struct stat *st) {
    return __cosmix_fstat(fd, st);
}

int __cosmix_stat(const char *__restrict__ path, struct stat *__restrict__ buf) {
	if (!IS_COSMIX_PTR(path) && !IS_COSMIX_PTR(buf))
	{
		return stat(path, buf);
	}

	// should actually allocate native and memcpy
	//
	UNSUPPORTED_FUNC();
}

int __cosmix_stat64(const char *__restrict__ path, struct stat *__restrict__ buf) {
    return __cosmix_stat(path, buf);
}

int __cosmix_lstat(const char *__restrict__ path, struct stat *__restrict__ buf) {
	if (!IS_COSMIX_PTR(path) && !IS_COSMIX_PTR(buf))
	{
		return lstat(path, buf);
	}

	// should actually allocate native and memcpy
	//
	UNSUPPORTED_FUNC();
}

int __cosmix_lstat64(const char *__restrict__ path, struct stat *__restrict__ buf) {
    return __cosmix_lstat(path, buf);
}

int __cosmix_unlink(const char *path) {
    if (!IS_COSMIX_PTR(path))
	{
		return unlink(path);
	}

	UNSUPPORTED_FUNC();
}

int __cosmix_mkdir(const char *path, mode_t mode) {
	if (!IS_COSMIX_PTR(path))
	{
		return mkdir(path, mode);
	}

	UNSUPPORTED_FUNC();
}

int __cosmix_rmdir(const char *path) {
	if (!IS_COSMIX_PTR(path))
	{
		return rmdir(path);
	}

	UNSUPPORTED_FUNC();	
}

ssize_t __cosmix_readlink(const char *__restrict__ path, char *__restrict__ buf, size_t bufsize) {
 	if (!IS_COSMIX_PTR(path) && !IS_COSMIX_PTR(buf))
	{
		return readlink(path, buf, bufsize);
	}

	UNSUPPORTED_FUNC();	   
}


size_t __cosmix_malloc_usable_size(void *ptr)
{
	if (!IS_COSMIX_PTR(ptr))
	{
		return malloc_usable_size(ptr);
	}

	size_t res;
	int topByte = (uintptr_t)ptr >> 60;
	
	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
			res = _0_mstore_alloc_size((void*)MAKE_ORIGINAL_POINTER(ptr));
			break;
		case MSTORE1_SHIFT60_VAL:
			res = _1_mstore_alloc_size((void*)MAKE_ORIGINAL_POINTER(ptr));
			break;
		case MSTORE2_SHIFT60_VAL:
			res = _2_mstore_alloc_size((void*)MAKE_ORIGINAL_POINTER(ptr));
			break;
		case MSTORE3_SHIFT60_VAL:
			res = _3_mstore_alloc_size((void*)MAKE_ORIGINAL_POINTER(ptr));
			break;
		default:
			abort();
	}

	return res;
}

#ifdef JEMALLOC

size_t __cosmix_je_malloc_usable_size(void* ptr)
{
	if (!IS_COSMIX_PTR(ptr))
	{
		return je_malloc_usable_size(ptr);
	}

	int topByte = (uintptr_t)ptr >> 60;
	
	switch (topByte)
	{
		case MSTORE0_SHIFT60_VAL:
			return _0_mstore_alloc_size((void*)MAKE_ORIGINAL_POINTER(ptr));
		case MSTORE1_SHIFT60_VAL:
			return _1_mstore_alloc_size((void*)MAKE_ORIGINAL_POINTER(ptr));
		case MSTORE2_SHIFT60_VAL:
			return _2_mstore_alloc_size((void*)MAKE_ORIGINAL_POINTER(ptr));
		case MSTORE3_SHIFT60_VAL:
			return _3_mstore_alloc_size((void*)MAKE_ORIGINAL_POINTER(ptr));
		default:
			abort();
	}
}

#endif

#endif

#ifdef __cplusplus
}
#endif
