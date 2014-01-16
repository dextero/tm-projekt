#include "generic_list.h"
#include "utils.h"

void **list_last_ptr__(void **list_ptr) {
    void **elem_pptr;

    if (!list_ptr) {
        return NULL;
    }

    LIST_FOREACH_PTR(elem_pptr, list_ptr) {
        if (!LIST_NEXT(*elem_pptr)) {
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

void **list_end_ptr__(void **list_ptr) {
    void **last_pptr = list_last_ptr__(list_ptr);

    if (!last_pptr) {
        return NULL;
    }

    if (*last_pptr) {
        return LIST_NEXT_PTR(*last_pptr);
    } else {
        return last_pptr;
    }
}

void *list_insert_new__(void **ptr, void *new_elem) {
    *LIST_NEXT_PTR(new_elem) = *ptr;
    *ptr = new_elem;
    return new_elem;
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

void test(void) {
    LIST(int) list = NULL;
    int *p, *p2;

    logInfo("%p == %p", &list, LIST_END_PTR(&list));

    p = LIST_APPEND_NEW(&list, int);
    *p = 100;
    logInfo("%p == %p", list, p);

    logInfo("%p = %p", LIST_NEXT_PTR(list), LIST_END_PTR(&list));

    logInfo("%p -> %p, %p -> %p", list, LIST_NEXT(list), p, LIST_NEXT(p));
    p2 = LIST_INSERT_NEW(&list, int);
    logInfo("%p -> %p, %p -> %p, %p -> %p", list, LIST_NEXT(list), p, LIST_NEXT(p), p2, LIST_NEXT(p2));
    logInfo("%p == %p", list, p2);
    logInfo("%p == %p", LIST_NEXT(p2), p);
}
