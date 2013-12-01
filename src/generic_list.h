#ifndef MIKRO_PROJEKT_GENERIC_LIST_H
#define MIKRO_PROJEKT_GENERIC_LIST_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define EXTRA_SPACE \
    sizeof(union { \
        void *voidPtr; \
        intmax_t intMax; \
    })

#ifdef HAVE_TYPEOF
#   define TYPE(var) typeof(var)*
#else
#   define TYPE(var) void*
#endif /* HAVE_TYPEOF */

void **list_last_ptr__(void **list_ptr);
void list_erase__(void **list_ptr);
size_t list_size__(void *list);

#ifdef OMG_MEMORY_CORRUPTION
static void *my_malloc(size_t size) {
    void *ret = malloc(size);
    logInfo("*** MALLOC %p", ret);
    return ret;
}

static void *my_calloc(size_t elems, size_t size) {
    void *ret = calloc(elems, size);
    logInfo("*** CALLOC %p", ret);
    return ret;
}

static void my_free(void *p) {
    logInfo("*** FREE %p", p);
    free(p);
}

#   define malloc my_malloc
#   define calloc my_calloc
#   define free my_free
#endif /* OMG_MEMORY_CORRUPTION */

#define LIST(type) type*

#define LIST_SIZE(list) list_size__(list)

#define LIST_NEXT(elem_ptr) \
    (*((TYPE(elem_ptr)*)(((char*)elem_ptr) - EXTRA_SPACE)))

#define LIST_FOREACH(elem_ptr, list) \
    for ((elem_ptr) = (list); (elem_ptr); (elem_ptr) = LIST_NEXT(elem_ptr))

#define LIST_FOREACH_PTR(elem_pptr, list_ptr) \
    for ((elem_pptr) = (list_ptr); \
         *(elem_pptr); \
         (elem_pptr) = (TYPE(*elem_pptr))((char*)(*(elem_pptr)) - EXTRA_SPACE))

#define LIST_LAST_PTR(list_ptr) \
    ((TYPE(list_ptr)*)list_last_ptr__((void**)list_ptr))

#define LIST_NEW_BUFFER(size) \
    ((char*)calloc(1, (size) + EXTRA_SPACE) + EXTRA_SPACE)

#define LIST_NEW_ELEMENT(type) \
    (type*)LIST_NEW_BUFFER(sizeof(type))

#define LIST_INSERT(next_pptr, elem_ptr) \
    ((*(TYPE(*(elem_ptr))*)((char*)(elem_ptr) - EXTRA_SPACE) = *(next_pptr)), \
     (*(next_pptr) = (elem_ptr)))

#define LIST_INSERT_NEW(next_pptr, type) \
    (type*)LIST_INSERT((next_pptr), LIST_NEW_ELEMENT(type))

#define LIST_APPEND(list_ptr, elem_ptr) \
    (*LIST_LAST_PTR(list_ptr) = (elem_ptr))

#define LIST_APPEND_NEW(list_ptr, type) \
    (type*)LIST_APPEND((list_ptr), LIST_NEW_ELEMENT(type))

#define LIST_ERASE(elem_ptr) list_erase__((void**)elem_ptr)

#define LIST_CLEAR(list_ptr) \
    for (; *(list_ptr); LIST_ERASE(list_ptr))

#endif /* MIKRO_PROJEKT_GENERIC_LIST_H */
