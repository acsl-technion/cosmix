/*
 * StoragePageTable.h
 * Used to store current EPC++ for SUVM/SPTR
 *
 *  Created on: Jul 17, 2016
 *      Author: user
 */

#ifndef _STORAGE_PAGETABLE_H_
#define _STORAGE_PAGETABLE_H_

#include "SyncUtils.h"
#include "../../include/common.h"
#include <string.h>


namespace storage
{
struct item_t
{
    int fd;
    int page_index;
    int epc_page_index;
    item_t *next;
    unsigned char ref_count;
    unsigned char is_dirty;
} __attribute__((packed));

struct bucket
{
    item_t* head;
    volatile unsigned char lock;
};

struct file_data
{
    int fd;
    int page_index;
};

// Simple queue used to implement a very simple FIFO eviction heuristic from the PageTable

class UsedPagesQueue
{
    private:
        int m_queue_size;
        unsigned long front, rear;
        file_data* q;
        volatile unsigned char _lock;
    public:
        UsedPagesQueue(int queue_size)
        {
            m_queue_size = queue_size;
            q = new file_data[queue_size];
            front = rear = 0;

            for (int i=0;i<queue_size;i++)
            {
                q[i].fd = -1;
                q[i].page_index = 0;
            }
        }

        ~UsedPagesQueue()
        {
            delete[] q;
        }

        int enqueue(const int& fd, const int page_index)
        {
            spin_lock(&_lock);

            if(rear-front == m_queue_size)
            {
                spin_unlock(&_lock);
                ASSERT(false);
                return -1;
            }

            int idx = rear % m_queue_size;
            q[idx].fd = fd;
            q[idx].page_index = page_index;
            ++rear;

            spin_unlock(&_lock);
            return 0;

        }

        void dequeue(int* fd, int* page_index)
        {
            spin_lock(&_lock);

            if(front == rear)
            {
                spin_unlock(&_lock);
                ASSERT(false);
                return;
            }

            file_data& result = q[front % m_queue_size];
            *fd = result.fd;
            *page_index = result.page_index;
            ++front;

            spin_unlock(&_lock);            
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
        int m_max_num_of_entries;

    public:        
        PageTable(size_t num_of_buckets, size_t page_cache_size)
        {
        	init(num_of_buckets, page_cache_size);
        }

        UsedPagesQueue* GetUsedPages()
        {
            return m_used_pages;
        }

        void init(size_t num_of_buckets, size_t max_num_of_entries)
        {
            m_max_num_of_entries = max_num_of_entries;
            m_hashmap_size = num_of_buckets;
            m_buckets = new bucket[num_of_buckets];

            for (size_t i=0;i<num_of_buckets;i++)
            {
                m_buckets[i].head = NULL;
                m_buckets[i].lock = 0;
            }

            m_used_pages = new UsedPagesQueue(m_max_num_of_entries);
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
        // Optimization note: This will lock the bucket, the unlock happens in remove
        item_t* get_page_index_to_evict()
        {
        	int num_of_tries = 0;

            // Only evicting pages with ref_count == 0.
            do
            {
            	ASSERT (num_of_tries < m_max_num_of_entries);

                int fd;
                int page_index;
                m_used_pages->dequeue(&fd, &page_index);

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

            return NULL;
        }

        item_t* get_internal(const int& fd, const int& page_index)
        {
			bucket& bkt = m_buckets[page_index % m_hashmap_size];
			item_t *p = bkt.head;

			while (p) {
				if (p->fd == fd && p->page_index == page_index) {
					return p;
				}

				p = p->next;
			}

			return NULL;
        }

        item_t* get(const int& fd, const int& page_index)
		{
			bucket& bkt = m_buckets[page_index % m_hashmap_size];
			spin_lock(&bkt.lock);
			item_t* ret = get_internal(fd, page_index);
            if (ret)
                ret->ref_count++;
			spin_unlock(&bkt.lock);
			return ret;
		}

        bool try_add(const int& fd, const int& page_index, const int& epc_page_index)
        {
            bucket& bkt = m_buckets[page_index % m_hashmap_size];
            spin_lock(&bkt.lock);
            item_t *p = bkt.head;
            item_t* tail = NULL;

            if (p == NULL) // no items yet in this bucket
            {
                item_t* it = new item_t();
                it->fd = fd;
                it->page_index = page_index;
                it->epc_page_index = epc_page_index;
                it->ref_count = 1;
                it->is_dirty = 0;
                it->next = NULL;
                bkt.head = it;
            }
            else
            {
                while (p)
                {
                    if (p->fd == fd && p->page_index == page_index) // already in list, just return it.
                    {			
                        spin_unlock(&bkt.lock);
                        return false;
                    }

                    tail = p;
                    p = p->next;
                }

                item_t* it = new item_t();
                it->fd = fd;
                it->page_index = page_index;
                it->epc_page_index = epc_page_index;
                it->ref_count = 1;
                it->is_dirty = 0;
                it->next = NULL;			
                tail->next = it;
            }

            m_used_pages->enqueue(fd, page_index);
            spin_unlock(&bkt.lock);

            return true;
        }

        int remove(const int& fd, const int& page_index)
        {
            bucket& bkt = m_buckets[page_index % m_hashmap_size];
            item_t* p = bkt.head;
            item_t* prev = NULL;
            int deleted_epc_page_index = -1;

            while (p)
            {
                if (p->fd == fd && p->page_index == page_index)
                {
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

        void update_entry(const int& fd, const int& page_index, char is_dirty, char ref_count_change)
        {
			bucket& bkt = m_buckets[page_index % m_hashmap_size];
			spin_lock(&bkt.lock);
			item_t* ret = get_internal(fd, page_index);
            ret->is_dirty |= is_dirty;
            ret->ref_count += ref_count_change;
			spin_unlock(&bkt.lock);
        }
};
} // storage

#endif /* PAGECACHE_H_ */
