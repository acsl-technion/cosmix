#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <vector>

class SlabAllocator
{
public:
    void init_slab(void* ptr, size_t slab_size, int min_alloc);
    void* alloc(size_t size);
    void free_alloc(void* ptr);
    size_t alloc_size(void* ptr);
private:
    struct alloc_metadata
    {
        void* ptr;
        size_t size;  
    };

    struct free_pages
    {
        void* start;
        size_t size;  
    };

    void* g_slab;
    uintptr_t g_current_alloc_ptr;
    int g_min_alloc;
    size_t g_slab_size;
    volatile unsigned char g_slab_lock;
    std::vector<free_pages> g_free_pages;
    std::vector<alloc_metadata> g_metadata;
};