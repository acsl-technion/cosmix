/*
 * mem.hpp
 *
 *  Created on: Jun 23, 2016
 *      Author: user
 */

#ifndef TRUSTEDLIB_LIB_SERVICES_STATIC_TRUSTED_MEM_ORAM_H_
#define TRUSTEDLIB_LIB_SERVICES_STATIC_TRUSTED_MEM_ORAM_H_

#include "stdlib.h"
#include  <assert.h>

namespace ORAM
{

// Minimum byte size per allocation
#define MN_REQ 16

#ifdef __cplusplus
extern "C" {
#endif

// memory management system taken for SQlite project (memsys5 memory allocator)

// Initialize with a buffer to allocate from (in SUVM the buffer is in the untrusted memory == BS)
int ORAMmemsys5Init(void *NotUsed, void* ptr, size_t p_size, int mnReq);
// Equivalent of free
void ORAMmemsys5Free(void *pOld);
// Equivalent of malloc
void *ORAMmemsys5Malloc(size_t nByte);
// Equivalent of realloc called with bigger size then orignally used
int ORAMmemsys5Roundup(int n);
// Returns the size of the pointer allocated. Very useful for implementing realloc on top of malloc
int ORAMmemsys5Size(void *p);

#ifdef __cplusplus
}
#endif

} // ORAM NAMESPACE

#endif /* TRUSTEDLIB_LIB_SERVICES_STATIC_TRUSTED_MEM_H_ */