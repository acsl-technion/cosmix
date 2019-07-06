#ifndef _ARRAY_TREE_H_
#define _ARRAY_TREE_H_

/**
 * Get the left child index in array
 * @param i Index of tree node
 * @return Index of left child node
 */
inline unsigned int left(unsigned int i)
{
    return (i << 1) + 1;
}

/**
 * Get the right child index in array
 * @param i Index of tree node
 * @return Index of right child node
 */
inline unsigned int right(unsigned int i)
{
    return (i << 1) + 2;
}

/**
 * Get the parent index
 * @param i Index of tree node
 * @return Index of the i-th node parent
 */
inline unsigned int parent(unsigned int i)
{
    return i == 0 ? 0 : (i - 1) >> 1;
}

#endif
