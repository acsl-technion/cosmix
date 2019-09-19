#pragma once
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Function declerations used by mstores for compiler to replace.
//
extern void* _real_malloc(size_t size);
#ifndef SDK_BUILD
extern int _real_open(const char* filename, int flags, ...);
extern int _real_close(int fd);
extern ssize_t _real_write(int fd, void* buf, size_t count);
extern ssize_t _real_read(int fd, void* buf, size_t count);
extern ssize_t _real_pread(int fd, void *buf, size_t size, off_t ofs);
extern ssize_t _real_pwrite(int fd, const void *buf, size_t size, off_t ofs);
#endif

#ifdef __cplusplus
}
#endif
