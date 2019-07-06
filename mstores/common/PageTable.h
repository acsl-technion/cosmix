/*
 * PageTable.h
 * Used to store current EPC++ for SUVM/SPTR
 *
 *  Created on: Jul 17, 2016
 *      Author: user
 */

#ifndef _PAGETABLE_H_
#define _PAGETABLE_H_

#include "SyncUtils.h"
#include "../../include/common.h"
#include <string.h>

struct item_t
{
    int bs_page_index;
    int epc_page_index;
    item_t *next;
} __attribute__((packed));

struct bucket
{
    item_t* head;
    volatile unsigned char lock;
};

// Simple queue used to implement a very simple FIFO eviction heuristic from the PageTable

class UsedPagesQueue
{
    private:
        int m_queue_size;
        unsigned long front, rear;
        int* q;
        volatile unsigned char _lock;
    public:
        UsedPagesQueue(int queue_size)
        {
            m_queue_size = queue_size;
            q = new int[queue_size];
            front = rear = 0;

            for (int i=0;i<queue_size;i++)
            {
                q[i] = -1;
            }
        }

        ~UsedPagesQueue()
        {
            delete[] q;
        }

        int enqueue(const int& elem)
        {
            spin_lock(&_lock);

            if(rear-front == m_queue_size)
            {
                spin_unlock(&_lock);
                ASSERT(false);
                return -1;
            }

            q[rear % m_queue_size] = elem;
            ++rear;

            spin_unlock(&_lock);
            return 0;

        }

        int dequeue()
        {
            spin_lock(&_lock);

            if(front == rear)
            {
                spin_unlock(&_lock);
                ASSERT(false);
                return -1;
            }

            int result = q[front % m_queue_size];
            ++front;

            spin_unlock(&_lock);

            return result;
        }

};

// This class implements a thread-safe cache for mapping between pages in a page cache to the pages in the mstorage
// Underline its a very simple hash table with open addressing collision resolution and fixed sized buckets
// While simple, it gives good results for memory demanding enclaves compared to stl unoredered_map due to setting the number of buckets to result 
// in low probability of collisions.
//
class PageTable
{
    private:

		bucket* m_buckets;
        size_t m_hashmap_size;
        UsedPagesQueue* m_used_pages;
        int m_max_page_cache_size;
        int m_backing_store_size;

    public:
        // Note: usage of int, we assume page cache size is always smaller than 2^sizeof(int).
        //
		int m_page_cache_size;

        PageTable(size_t num_of_buckets, size_t backing_store_size, size_t page_cache_size)
        {
        	init(num_of_buckets, backing_store_size, page_cache_size);
        }

        int debug_ref_count(volatile char* volatile ref_count) {
        	volatile int acc = 0;
        	for (int i=0;i<m_backing_store_size;i++) {
        		acc += ref_count[i*2];
        	}

        	return acc;
        }

        void init(size_t num_of_buckets, size_t backing_store_size, size_t page_cache_size)
        {
            m_page_cache_size =0;
            m_max_page_cache_size = page_cache_size;
            m_hashmap_size = num_of_buckets;
            m_buckets = new bucket[num_of_buckets];

            for (size_t i=0;i<num_of_buckets;i++)
            {
                m_buckets[i].head = NULL;
                m_buckets[i].lock = 0;
            }

            m_used_pages = new UsedPagesQueue(page_cache_size);		
            m_backing_store_size = backing_store_size;
        }

        void cleanup()
        {
        	delete m_used_pages;

        	for (size_t i=0;i<m_hashmap_size;i++)
			{
				item_t* p = m_buckets[i].head;
				while (p)
				{
					item_t* to_delete = p;
					p = p->next;
					delete to_delete;
				}
			}

            delete[] m_buckets;
            m_buckets = NULL;
        }

        // This method is reponsible for the eviction policy and removing the page from the page cache
        // Optimization note: This will lock the bucket, the unlock happens in remove method call
        //
        item_t* get_page_index_to_evict(volatile char* volatile ref_count)
        {
        	int num_of_tries = 0;

            // Only evicting pages with ref_count == 0.
            //
            int page_index = -1;	
            do
            {
            	ASSERT (num_of_tries < m_max_page_cache_size);

                page_index = m_used_pages->dequeue();

                bucket& bkt = m_buckets[page_index % m_hashmap_size];
                spin_lock(&bkt.lock);

                if (ref_count[page_index * 2] > 0)
                {
                    spin_unlock(&bkt.lock);
                    m_used_pages->enqueue(page_index);
                    num_of_tries++;
                }
                else
                {
                    item_t* ret = get_internal(page_index);
                    ASSERT (ret != NULL);
                    return ret;
                }
            }
            while (true);
            return NULL;
        }

        item_t* get_internal(const int& page_index)
        {
			bucket& bkt = m_buckets[page_index % m_hashmap_size];
			item_t *p = bkt.head;

			while (p) {
				if (p->bs_page_index == page_index) {
					return p;
				}

				p = p->next;
			}

			return NULL;
        }

        item_t* get(const int& page_index, bool dirty)
		{
			bucket& bkt = m_buckets[page_index % m_hashmap_size];
			spin_lock(&bkt.lock);
			item_t* ret = NULL; // get_internal(page_index);

			item_t *p = bkt.head;

			while (p) {
				if (p->bs_page_index == page_index) {
					ret = p;
                    // Note: dirty is updated outside of the page table for performance reasons
					//ret->is_read_only &= !dirty;
					break;
				}

				p = p->next;
			}

			spin_unlock(&bkt.lock);
			return ret;
		}

        bool try_add(const int& page_index, const int& epc_page_index, bool dirty)
        {
            bucket& bkt = m_buckets[page_index % m_hashmap_size];
            spin_lock(&bkt.lock);
            item_t *p = bkt.head;
            item_t* tail = NULL;

            if (p == NULL) // no items yet in this bucket
            {
                item_t* it = new item_t();
                it->bs_page_index = page_index;
                it->epc_page_index = epc_page_index;
                // Note: dirty is updated outside of the page table for performance reasons
                //it->is_read_only = !dirty; 
                it->next = NULL;
                bkt.head = it;
            }
            else
            {
                while (p)
                {
                    if (p->bs_page_index == page_index) // already in list, just return it.
                    {			
                        spin_unlock(&bkt.lock);
                        return false;
                    }

                    tail = p;
                    p = p->next;
                }

                item_t* it = new item_t();
                it->bs_page_index = page_index;
                it->epc_page_index = epc_page_index;
                // Note: dirty is updated outside of the page table for performance reasons
                //it->is_read_only = !dirty; 
                it->next = NULL;			
                tail->next = it;
            }


            __sync_fetch_and_add( &m_page_cache_size, 1);
            m_used_pages->enqueue(page_index);
            spin_unlock(&bkt.lock);

            return true;
        }

        int remove(const int& page_index)
        {
            bucket& bkt = m_buckets[page_index % m_hashmap_size];
            item_t* p = bkt.head;
            item_t* prev = NULL;
            int deleted_epc_page_index = -1;

            while (p)
            {
                if (p->bs_page_index == page_index)
                {
                    __sync_fetch_and_add( &m_page_cache_size, -1);

                    if (prev == NULL) // head of the list
                    {
                        if (p->next == NULL) // single item in this bucket
                        {
                            bkt.head = NULL;						
                            deleted_epc_page_index = p->epc_page_index;
                            delete p;
                        }
                        else // replace head of the bucket
                        {
                            bkt.head = p->next;
                            deleted_epc_page_index = p->epc_page_index;
                            delete p;
                        }
                    }
                    else // replace linkage
                    {
                        prev->next = p->next;
                        deleted_epc_page_index = p->epc_page_index;
                        delete p;
                    }

                    spin_unlock(&bkt.lock);
                    return 0;
                }

                prev = p;
                p = p->next;		
            }

            ASSERT(false);
            spin_unlock(&bkt.lock);
            return 0;
        }
};

#endif /* PAGECACHE_H_ */
