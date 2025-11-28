
#include "fifo.h"
#include <stdint.h>
#include <stdlib.h>

/*
 * Create an empty FIFO node acting as the sentinel head.
 * The returned node forms a circular doubly-linked list
 * where head->next == head and head->prev == head.
 *
 * Returns:
 *   struct fifo_node*  Pointer to the newly allocated head.
 *   NULL               Allocation failure.
 */
struct fifo_node* fifo_mk_empty()
{
    struct fifo_node* n = malloc(sizeof(struct fifo_node));
    
    if (!n)
        return NULL;

    n->data = 0;
    n->next = n;
    n->prev = n;

    return n;
}

/*
 * Compute the number of data nodes currently stored in the FIFO.
 * The head itself is not counted. The traversal stops when it
 * loops back to the head.
 *
 * Parameters:
 *   head - Pointer to the sentinel node.
 *
 * Returns:
 *   >=0   Number of data nodes.
 *   -1    Invalid head pointer.
 */
int fifo_size(struct fifo_node* head)
{
    if (!head) 
        return -1;

    int sum = 0;
    struct fifo_node* n = head;

    while(n->next != head && n->next)
    {
        sum += 1;
        n = n->next;
    }

    return sum;
}

/*
 * Push a new data element into the FIFO.
 * The new node is inserted immediately after the head,
 * effectively treating head->prev as the tail for pop operations.
 *
 * Parameters:
 *   head - Pointer to the sentinel node.
 *   data - The value to insert.
 *
 * Returns:
 *   0     Success.
 *   -1    Invalid head or allocation failure.
 */
int fifo_push(struct fifo_node* head, uint64_t data)
{
    if (!head || !head->next || !head->prev) 
        return -1;

    struct fifo_node* n = malloc(sizeof(struct fifo_node));
    struct fifo_node* old_next = head->next;

    if (!n)
        return -1;

    n->prev = head;
    n->next = head->next;

    head->next = n;
    old_next->prev = n;

    n->data = data;

    return 0;
}

/*
 * Pop the oldest element from the FIFO.
 * The element is taken from head->prev (the tail node).
 *
 * Parameters:
 *   head - Pointer to the sentinel node.
 *   data - Output pointer receiving the popped value.
 *
 * Returns:
 *   0     Success.
 *   -1    Invalid parameters or empty FIFO.
 */
int fifo_pop(struct fifo_node* head, uint64_t* data)
{
    if (!head || !data || (head->prev == head) || (head->next == head) || !head->next || !head->prev) 
        return -1;

    struct fifo_node* n = head->prev;

    head->prev = n->prev;
    n->prev->next = head;

    *data = n->data;
    free(n);

    return 0;
}