#ifndef __SUVM_COMMON_H_
#define __SUVM_COMMON_H_

#include <stdlib.h>
#include <stdint.h>

struct s_file_alloc_privdata
{
    void *start;
    // size_t len; 
    int prot;
    int flags;
    int fd;
    off_t off;
    char alloc_succeeded;
};

/* Useful MACROS */
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define BIT_SIZE 8
#define INLINEATTR __attribute__((always_inline))

#define DBG_PRINT

#ifdef JEMALLOC

#define cosmix_malloc je_malloc
#define cosmix_calloc je_calloc
#define cosmix_realloc je_realloc
#define cosmix_memalign memalign
#define cosmix_free je_free

#else

#define cosmix_malloc malloc
#define cosmix_calloc calloc
#define cosmix_realloc realloc
#define cosmix_memalign memalign
#define cosmix_free free

#endif


#ifdef __cplusplus
extern "C" {
#endif

typedef void (*DBG_FUNC)(const char *fmt, ...);
extern DBG_FUNC g_debug;

#ifdef __cplusplus
}
#endif


#define UNSUPPORTED_FUNC()\
    do\
    {\
        g_debug("Function not supported file = %s, line = %d", __FILE__, __LINE__); \
        abort(); \
    } while(0)


#ifndef RELEASE_BUILD

#define ASSERT(cond)\
         do\
     {\
              if (!(cond))\
              {\
                           g_debug("ASSERTION FAILED: cond = %s, file = %s, line = %d, 0 = %d\n", #cond,     __FILE__, __LINE__, 0);\
                           abort();\
                       }\
          } while(0)


#define INC_COUNTER(x) __sync_fetch_and_add(&(x), 1)

#else

#define ASSERT(cond)
#define INC_COUNTER(x)

#warning "**********************RELEASE BUILD - ASSERTIONS DISABLED ************************"
#endif

// Note: not suported anymore after the refactoring   
#ifdef RANGE_CHECK

// This is a range check on BS    
#define IS_SUVM_UNLINKED_PTR(X) \
	(((((uintptr_t)(X) - g_base_backing_store_ptr) & ~BS_MASK) == 0))

// This is a range check on SUVM's page cache
// #define IS_SUVM_LINKED_PTR(X) \
//     ((((((uintptr_t)(X)) - g_base_page_cache_ptr) & ~PAGE_CACHE_MASK) == 0))

#define MAKE_BS_PTR(X) (X)

// #define MAKE_PAGE_CACHE_PTR(X) (X)

#define MAKE_ORIGINAL_POINTER(X) (X)

#else

// COSMIX ptr has the MSB (bit 63) set
//
#define COSMIX_BIT_MASK 0x8000000000000000

// UNTRUSTED_BS ptrs has bit 63+62 set
#define UNTRUSTED_BS_BIT_MASK 0xc000000000000000

// DISK_BS ptrs has bit 63+61 set
#define DISK_BS_BIT_MASK 0xa000000000000000

// ORAM_BS ptrs has bit 63+60 set
#define ORAM_BS_BIT_MASK 0x9000000000000000

// COMP_BS ptrs has bit 63+60+61 set
#define COMP_BS_BIT_MASK 0xb000000000000000

// clear the 4 upper msbs
#define CLEAR_BIT_MASK 0x0fffffffffffffff

// This is a msb check on BS
#define IS_COSMIX_PTR(X) \
	((((uintptr_t)(X) & COSMIX_BIT_MASK)) == COSMIX_BIT_MASK)

#define IS_ORAM_PTR(X) \
    ((((uintptr_t)(X) & ORAM_BS_BIT_MASK)) == ORAM_BS_BIT_MASK)

#define IS_COMP_PTR(X) \
    ((((uintptr_t)(X) & COMP_BS_BIT_MASK)) == COMP_BS_BIT_MASK)

#define IS_SUVM_PTR(X) \
    ((((uintptr_t)(X) & UNTRUSTED_BS_BIT_MASK)) == UNTRUSTED_BS_BIT_MASK)

#define IS_STORAGE_PTR(X) \
    ((((uintptr_t)(X) & DISK_BS_BIT_MASK)) == DISK_BS_BIT_MASK)

#define MAKE_UNTRUSTED_BS_PTR(X) \
		((uintptr_t)(X) | UNTRUSTED_BS_BIT_MASK)

#define MAKE_DISK_BS_PTR(X) \
		((uintptr_t)(X) | DISK_BS_BIT_MASK)

#define MAKE_ORAM_BS_PTR(X) \
		((uintptr_t)(X) | ORAM_BS_BIT_MASK)

#define MAKE_COMP_BS_PTR(X) \
		((uintptr_t)(X) | COMP_BS_BIT_MASK)

#define MAKE_ORIGINAL_POINTER(X) \
		(((uintptr_t)(X) & CLEAR_BIT_MASK))

// UNTRUSTED_BS ptrs has bit 63+62 set
#define MSTORE0_BIT_MASK 0xc000000000000000

// DISK_BS ptrs has bit 63+61 set
#define MSTORE1_BIT_MASK 0xa000000000000000

// ORAM_BS ptrs has bit 63+60 set
#define MSTORE2_BIT_MASK 0x9000000000000000

// COMP_BS ptrs has bit 63+60+61 set
#define MSTORE3_BIT_MASK 0xb000000000000000

#define MSTORE0_SHIFT60_VAL 12
#define MSTORE1_SHIFT60_VAL 10
#define MSTORE2_SHIFT60_VAL 9
#define MSTORE3_SHIFT60_VAL 11

#define MAKE_MSTORE0_PTR(X) \
		((uintptr_t)(X) | MSTORE0_BIT_MASK)

#define MAKE_MSTORE1_PTR(X) \
		((uintptr_t)(X) | MSTORE1_BIT_MASK)

#define MAKE_MSTORE2_PTR(X) \
		((uintptr_t)(X) | MSTORE2_BIT_MASK)

#define MAKE_MSTORE3_PTR(X) \
		((uintptr_t)(X) | MSTORE3_BIT_MASK)


#endif

#endif
