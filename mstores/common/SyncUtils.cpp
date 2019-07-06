/*
 * SyncUtils.cpp
 *
 *  Created on: Jun 23, 2016
 *      Author: user
 */

#include "SyncUtils.h"
#include "../../include/common.h"

void spin_lock(unsigned char volatile *p)
{
    while(!__sync_bool_compare_and_swap(p, 0, 1))
    {
        while(*p) __asm__("pause");
    }
}

void spin_unlock(unsigned char volatile *p)
{
    __asm__ volatile (""); // acts as a memory barrier.
    *p = 0;
}