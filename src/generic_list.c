#include "generic_list.h"

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

#include "utils.h"

void test_list(void) {
    {
        LIST(int) list = NULL;
        int *elem = LIST_NEW_ELEMENT(int);
        
        LIST_APPEND(&list, elem);
        logInfo("append 0: %s", LIST_SIZE(list) == 1 ? "OK" : "ERROR");
    }
    {
        LIST(int) list = NULL;
        int *elem = LIST_NEW_ELEMENT(int);
        int *elem2 = LIST_NEW_ELEMENT(int);

        LIST_APPEND(&list, elem);
        LIST_APPEND(&list, elem2);
        logInfo("append 1: %s",
                (!LIST_LAST_PTR(&list)) ? "ERROR (last_ptr is null)" :
                (LIST_LAST(&list) != elem2) ? "ERROR (invalid last)" :
                (!LIST_NEXT(list)) ? "ERROR (no second value)" :
                (LIST_SIZE(list) != 2) ? "ERROR (size)" : "OK");
    }
    {
        LIST(int) list = NULL;
        int *elem = LIST_NEW_ELEMENT(int);
        int *elem2 = LIST_NEW_ELEMENT(int);

        *elem = 1;
        *elem2 = 2;
        
        LIST_APPEND(&list, elem);
        LIST_APPEND(&list, elem2);
        logInfo("append 2: %s",
                (LIST_SIZE(list) != 2) ? "ERROR (size)" :
                (*list != 1) ? "ERROR (first value)" :
                (!LIST_NEXT(list)) ? "ERROR (no second value" :
                (*LIST_NEXT(list) != 2) ? "ERROR (second value)" : "OK");
    }
}
