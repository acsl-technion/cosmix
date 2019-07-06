/*
** 2007 October 14
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** This file contains the C functions that implement a memory
** allocation subsystem for use by SQLite.
**
** This version of the memory allocation subsystem omits all
** use of malloc(). The application gives SQLite a block of memory
** before calling sqlite3_initialize() from which allocations
** are made and returned by the xMalloc() and xRealloc()
** implementations. Once sqlite3_initialize() has been called,
** the amount of memory available to SQLite is fixed and cannot
** be changed.
**
** This version of the memory allocation subsystem is included
** in the build only if SQLITE_ENABLE_MEMSYS5 is defined.
**
** This memory allocator uses the following algorithm:
**
**   1.  All memory allocation sizes are rounded up to a power of 2.
**
**   2.  If two adjacent free blocks are the halves of a larger block,
**       then the two blocks are coalesced into the single larger block.
**
**   3.  New memory is allocated from the first available free block.
**
** This algorithm is described in: J. M. Robson. "Bounds for Some Functions
** Concerning Dynamic Storage Allocation". Journal of the Association for
** Computing Machinery, Volume 21, Number 8, July 1974, pages 491-499.
**
** Let n be the size of the largest allocation divided by the minimum
** allocation size (after rounding all sizes up to a power of 2.)  Let M
** be the maximum amount of memory ever outstanding at one time.  Let
** N be the total amount of memory available for allocation.  Robson
** proved that this memory allocator will never breakdown due to
** fragmentation as long as the following constraint holds:
**
**      N >=  M*(1 + log2(n)/2) - n + 1
**
** The sqlite3_status() logic tracks the maximum values of n and M so
** that an application can, at any time, verify this constraint.
*/

#ifndef TRUSTEDLIB_LIB_SERVICES_STATIC_TRUSTED_MEM_UNTRUSTED_H_
#define TRUSTEDLIB_LIB_SERVICES_STATIC_TRUSTED_MEM_UNTRUSTED_H_

#include "stdlib.h"
#include  <assert.h>

// Minimum byte size per allocation
#define MN_REQ 16

#ifdef __cplusplus
extern "C" {
#endif

// Note: this is a memory management system taken from SQlite project (memsys5 memory allocator)

// Initialize with a buffer to allocate from (in SUVM the buffer is in the untrusted memory == BS)
int Untrustedmemsys5Init(void *NotUsed, void* ptr, size_t p_size, int mnReq);
// Equivalent of free
void Untrustedmemsys5Free(void *pOld);
// Equivalent of malloc
void *Untrustedmemsys5Malloc(size_t nByte);
// Equivalent of realloc called with bigger size then orignally used
int Untrustedmemsys5Roundup(int n);
// Returns the size of the pointer allocated. Very useful for implementing realloc on top of malloc
int Untrustedmemsys5Size(void *p);
// realloc
void *Untrustedmemsys5Realloc(void *pPrior, int nBytes);

#ifdef __cplusplus
}
#endif

#endif /* TRUSTEDLIB_LIB_SERVICES_STATIC_TRUSTED_MEM_H_ */
