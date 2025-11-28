#pragma once
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fifo_node {
    struct fifo_node *prev;
    struct fifo_node *next;
    uint64_t data;
};

struct fifo_node* fifo_mk_empty();
int fifo_size(struct fifo_node* head);
int fifo_push(struct fifo_node* head, uint64_t data);
int fifo_pop(struct fifo_node* head, uint64_t* data);

#ifdef __cplusplus
}
#endif