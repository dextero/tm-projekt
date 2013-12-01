#include "generic_list.h"

void **list_last_ptr__(void **list_ptr) {
    void **last = list_ptr;
    void **next;

    LIST_FOREACH_PTR(next, list_ptr) {
        last = next;
    }

    return last;
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
