#include "generic_list.h"

#include <stdlib.h>

void **list_last_ptr__(void **list_ptr) {
    void **elem_pptr;

    LIST_FOREACH_PTR(elem_pptr, list_ptr) {
        if (!LIST_NEXT_PTR(*elem_pptr)) {
            return elem_pptr;
        }
    }

    return elem_pptr;
}

void *list_last__(void *list) {
    void *elem;

    LIST_FOREACH(elem, list) {
        if (!LIST_NEXT(elem)) {
            return elem;
        }
    }

    return NULL;
}

void list_erase__(void **list_ptr) {
    if (list_ptr) {
        void *next = LIST_NEXT(*list_ptr);
        free((char*)*list_ptr - EXTRA_SPACE);
        *list_ptr = next;
    }
}

size_t list_size__(void *list) {
    size_t size = 0;
    void *next;

    LIST_FOREACH(next, list) {
        ++size;
    }

    return size;
}

