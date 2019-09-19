#include "slab_allocator.h"
#include "SyncUtils.h"
#include "../../include/common.h"
#include "stdio.h"

void SlabAllocator::init_slab(void* ptr, size_t slab_size, int min_alloc)
{
    g_slab = ptr;
    g_current_alloc_ptr = (uintptr_t) ptr;
    g_slab_size = slab_size;
    g_min_alloc = min_alloc;
}

void* SlabAllocator::alloc(size_t size)
{
    // always allocate aligned ptrs
    if (size % g_min_alloc != 0)
    {
        size += g_min_alloc;
        size &= ~(g_min_alloc-1);
    }

    spin_lock(&g_slab_lock);

    if (g_current_alloc_ptr + size <= (uintptr_t)g_slab + g_slab_size)
    {
        alloc_metadata md = { (void*)g_current_alloc_ptr, size };
        g_metadata.push_back(md);
        g_current_alloc_ptr += size;

        spin_unlock(&g_slab_lock);
        return (void*)md.ptr;
    }

    // otherwise, slow path - go over free list
    for (auto& fp : g_free_pages)
    {
        if (fp.size >= size)
        {
            alloc_metadata md = { (void*)fp.start, size };
            g_metadata.push_back(md);

            size_t left_bytes = fp.size - size;
            
            // update free space
            //
            if (left_bytes > 0)
            {
                fp.start = (void*)((uintptr_t)fp.start+size);
                fp.size = left_bytes;
            }

            spin_unlock(&g_slab_lock);
        }
    }

    g_debug("Cannot find space to allocate request for size %ld. aborting\n", size);
    abort();
}

void SlabAllocator::free_alloc(void* ptr)
{
    spin_lock(&g_slab_lock);

    // go over metadata, and add to free
    for (auto it = g_metadata.begin(); it != g_metadata.end(); it++)
    {
        if (it->ptr == ptr)
        {
            free_pages fp = { it->ptr, it->size };
            g_free_pages.push_back(fp);
            g_metadata.erase(it);
            spin_unlock(&g_slab_lock);
            return;
        }
    }

    g_debug("Cannot free since cannot find allocation ptr %p\n", ptr);
    abort();
}

size_t SlabAllocator::alloc_size(void* ptr)
{
    spin_lock(&g_slab_lock);

    // go over struct to find the size
    for (auto& md : g_metadata)
    {
        if (md.ptr == ptr)
        {
            spin_unlock(&g_slab_lock);
            return md.size;
        }
    }

    g_debug("Cannot find allocation size for ptr %p\n", ptr);
    abort();
}
