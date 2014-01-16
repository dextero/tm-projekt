#include <stdio.h>

#include "test.h"
#include "utils.h"
#include "generic_list.h"
#include "generic_list.c"

TEST_CASE(next) {
    struct {
        union extra_space_union__ extraSpace;
        int element;
    } listElem;

    listElem.extraSpace.voidPtr = &listElem;

    ASSERT_EQ(listElem.extraSpace.voidPtr, LIST_NEXT(&listElem.element));

    return TEST_SUCCESS;
}

TEST_CASE(next_ptr) {
    struct {
        union extra_space_union__ extraSpace;
        int element;
    } listElem;

    listElem.extraSpace.voidPtr = &listElem;

    ASSERT_EQ((void*)&listElem.extraSpace, (void*)LIST_NEXT_PTR(&listElem.element));

    return TEST_SUCCESS;
}

TEST_CASE(new_buffer) {
    void *buf = LIST_NEW_BUFFER(32);

    ASSERT_NEQ(NULL, (void*)buf);
    ASSERT_EQ(NULL, (void*)LIST_NEXT(buf));

    LIST_CLEAR(&buf);
    return TEST_SUCCESS;
}

TEST_CASE(new_element) {
    int *elem = LIST_NEW_ELEMENT(int);

    ASSERT_NEQ(NULL, (void*)elem);
    ASSERT_EQ(NULL, (void*)LIST_NEXT(elem));

    LIST_CLEAR(&elem);
    return TEST_SUCCESS;
}

TEST_CASE(insert) {
    int *first = LIST_NEW_ELEMENT(int);
    int *second = LIST_NEW_ELEMENT(int);
    int *third = LIST_NEW_ELEMENT(int);
    int *saved_second = second;
    int *fourth = LIST_NEW_ELEMENT(int);

    *first = 1;
    *second = 2;
    *third = 3;
    *fourth = 4;

    LIST_INSERT(&second, first);

    ASSERT_EQ((void*)first, (void*)second);
    ASSERT_EQ((void*)saved_second, (void*)LIST_NEXT(first));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(saved_second));

    LIST_INSERT(LIST_NEXT_PTR(first), third);

    ASSERT_EQ((void*)first, (void*)second);
    ASSERT_EQ((void*)third, (void*)LIST_NEXT(first));
    ASSERT_EQ((void*)saved_second, (void*)LIST_NEXT(third));

    LIST_INSERT(LIST_NEXT_PTR(saved_second), fourth);

    ASSERT_EQ((void*)saved_second, (void*)LIST_NEXT(third));
    ASSERT_EQ((void*)fourth, (void*)LIST_NEXT(saved_second));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(fourth));

    ASSERT_EQ(1, *first);
    ASSERT_EQ(3, *LIST_NEXT(first));
    ASSERT_EQ(2, *LIST_NEXT(LIST_NEXT(first)));
    ASSERT_EQ(4, *LIST_NEXT(LIST_NEXT(LIST_NEXT(first))));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(LIST_NEXT(first)))));

    LIST_CLEAR(&first);
    return TEST_SUCCESS;
}

TEST_CASE(insert_new) {
    int *second = LIST_NEW_ELEMENT(int);
    int *saved_second = second;
    int *first = LIST_INSERT_NEW(&second, int);
    int *third;
    int *fourth;

    ASSERT_NEQ(NULL, (void*)first);
    ASSERT_NEQ(NULL, (void*)second);

    *first = 1;
    *saved_second = 2;

    ASSERT_EQ((void*)first, (void*)second);
    ASSERT_EQ((void*)saved_second, (void*)LIST_NEXT(first));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(saved_second));

    ASSERT_EQ(1, *first);
    ASSERT_EQ(2, *LIST_NEXT(first));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(first)));

    third = LIST_INSERT_NEW(LIST_NEXT_PTR(first), int);

    ASSERT_NEQ(NULL, (void*)third);
    *third = 3;

    ASSERT_EQ((void*)third, (void*)LIST_NEXT(first));
    ASSERT_EQ((void*)saved_second, (void*)LIST_NEXT(third));

    ASSERT_EQ(1, *first);
    ASSERT_EQ(3, *LIST_NEXT(first));
    ASSERT_EQ(2, *LIST_NEXT(LIST_NEXT(first)));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(first))));

    fourth = LIST_INSERT_NEW(LIST_NEXT_PTR(saved_second), int);

    ASSERT_NEQ(NULL, (void*)fourth);
    *fourth = 4;

    ASSERT_EQ((void*)fourth, (void*)LIST_NEXT(saved_second));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(fourth));

    ASSERT_EQ(1, *first);
    ASSERT_EQ(3, *LIST_NEXT(first));
    ASSERT_EQ(2, *LIST_NEXT(LIST_NEXT(first)));
    ASSERT_EQ(4, *LIST_NEXT(LIST_NEXT(LIST_NEXT(first))));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(LIST_NEXT(first)))));

    LIST_CLEAR(&first);
    return TEST_SUCCESS;
}

TEST_CASE(foreach) {
    LIST(int) list = NULL;

    int *fourth = LIST_INSERT_NEW(&list, int);
    int *third = LIST_INSERT_NEW(&list, int);
    int *second = LIST_INSERT_NEW(&list, int);
    int *first = LIST_INSERT_NEW(&list, int);

    int *curr;
    int loops = 0;

    *first = 1;
    *second = 2;
    *third = 3;
    *fourth = 4;

    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ((void*)second, (void*)LIST_NEXT(list));
    ASSERT_EQ((void*)third, (void*)LIST_NEXT(LIST_NEXT(list)));
    ASSERT_EQ((void*)fourth, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(list))));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(LIST_NEXT(list)))));

    LIST_FOREACH(curr, list) {
        ++loops;
        ASSERT_EQ(*curr, loops);
        if (loops == 1) ASSERT_EQ((void*)first, (void*)curr);
        else if (loops == 2) ASSERT_EQ((void*)second, (void*)curr);
        else if (loops == 3) ASSERT_EQ((void*)third, (void*)curr);
        else if (loops == 4) ASSERT_EQ((void*)fourth, (void*)curr);
    }

    ASSERT_EQ(4, loops);

    LIST_CLEAR(&list);
    return TEST_SUCCESS;
}

TEST_CASE(foreach_ptr) {
    LIST(int) list = NULL;

    int *fourth = LIST_INSERT_NEW(&list, int);
    int *third = LIST_INSERT_NEW(&list, int);
    int *second = LIST_INSERT_NEW(&list, int);
    int *first = LIST_INSERT_NEW(&list, int);

    int **curr;
    int loops = 0;

    *first = 1;
    *second = 2;
    *third = 3;
    *fourth = 4;

    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ((void*)second, (void*)LIST_NEXT(list));
    ASSERT_EQ((void*)third, (void*)LIST_NEXT(LIST_NEXT(list)));
    ASSERT_EQ((void*)fourth, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(list))));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(LIST_NEXT(list)))));

    LIST_FOREACH_PTR(curr, &list) {
        ++loops;
        ASSERT_EQ(**curr, loops);
        if (loops == 1) ASSERT_EQ((void*)&list, (void*)curr);
        else if (loops == 2) ASSERT_EQ((void*)LIST_NEXT_PTR(first), (void*)curr);
        else if (loops == 3) ASSERT_EQ((void*)LIST_NEXT_PTR(second), (void*)curr);
        else if (loops == 4) ASSERT_EQ((void*)LIST_NEXT_PTR(third), (void*)curr);
    }

    ASSERT_EQ(4, loops);

    LIST_CLEAR(&list);
    return TEST_SUCCESS;
}

TEST_CASE(last) {
    int *first = LIST_NEW_ELEMENT(int);
    int *second;

    ASSERT_EQ(NULL, LIST_LAST(NULL));
    ASSERT_EQ(first, LIST_LAST(first));
    second = LIST_INSERT_NEW(LIST_NEXT_PTR(first), int);
    ASSERT_EQ(second, LIST_LAST(first));

    LIST_CLEAR(&first);
    return TEST_SUCCESS;
}

TEST_CASE(last_ptr) {
    int *first = LIST_NEW_ELEMENT(int);

    ASSERT_EQ(NULL, (void*)LIST_LAST_PTR(NULL));
    ASSERT_EQ((void*)&first, (void*)LIST_LAST_PTR(&first));
    LIST_INSERT_NEW(LIST_NEXT_PTR(first), int);
    ASSERT_EQ((void*)LIST_NEXT_PTR(first), (void*)LIST_LAST_PTR(&first));

    LIST_CLEAR(&first);
    return TEST_SUCCESS;
}

TEST_CASE(end_ptr) {
    int *first = LIST_NEW_ELEMENT(int);
    int *second;

    ASSERT_EQ(NULL, (void*)LIST_END_PTR(NULL));
    ASSERT_EQ((void*)LIST_NEXT_PTR(first), (void*)LIST_END_PTR(&first));
    ASSERT_EQ(NULL, (void*)*LIST_END_PTR(&first));
    second = LIST_INSERT_NEW(LIST_NEXT_PTR(first), int);
    ASSERT_EQ((void*)LIST_NEXT_PTR(second), (void*)LIST_END_PTR(&first));
    ASSERT_EQ((void*)LIST_END_PTR(&first), (void*)LIST_END_PTR(LIST_NEXT_PTR(first)));
    ASSERT_EQ(NULL, (void*)*LIST_END_PTR(&first));

    LIST_CLEAR(&first);
    return TEST_SUCCESS;
}

TEST_CASE(append) {
    LIST(int) list = NULL;
    int *first = LIST_NEW_ELEMENT(int);
    int *second = LIST_NEW_ELEMENT(int);
    int *third = LIST_NEW_ELEMENT(int);

    ASSERT_EQ(NULL, (void*)list);

    LIST_APPEND(&list, first);
    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ(NULL, (void*)LIST_NEXT(list));

    LIST_APPEND(&list, second);
    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ((void*)second, (void*)LIST_NEXT(list));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(list)));

    LIST_APPEND(&list, third);
    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ((void*)second, (void*)LIST_NEXT(list));
    ASSERT_EQ((void*)third, (void*)LIST_NEXT(LIST_NEXT(list)));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(list))));

    LIST_CLEAR(&list);
    return TEST_SUCCESS;
}

TEST_CASE(append_new) {
    LIST(int) list = NULL;
    int *first;
    int *second;
    int *third;

    ASSERT_EQ(NULL, (void*)list);

    first = LIST_APPEND_NEW(&list, int);
    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ(NULL, (void*)LIST_NEXT(list));

    second = LIST_APPEND_NEW(&list, int);
    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ((void*)second, (void*)LIST_NEXT(list));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(list)));

    third = LIST_APPEND_NEW(&list, int);
    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ((void*)second, (void*)LIST_NEXT(list));
    ASSERT_EQ((void*)third, (void*)LIST_NEXT(LIST_NEXT(list)));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(list))));

    LIST_CLEAR(&list);
    return TEST_SUCCESS;
}

TEST_CASE(size) {
    LIST(int) list = NULL;

    ASSERT_EQ(0U, LIST_SIZE(list));
    LIST_INSERT_NEW(&list, int);
    ASSERT_EQ(1U, LIST_SIZE(list));
    LIST_INSERT_NEW(&list, int);
    ASSERT_EQ(2U, LIST_SIZE(list));

    LIST_CLEAR(&list);
    return TEST_SUCCESS;
}

TEST_CASE(clear) {
    LIST(int) list = NULL;

    int *fourth = LIST_INSERT_NEW(&list, int);
    int *third = LIST_INSERT_NEW(&list, int);
    int *second = LIST_INSERT_NEW(&list, int);
    int *first = LIST_INSERT_NEW(&list, int);

    int *curr;
    int loops = 0;

    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ((void*)second, (void*)LIST_NEXT(list));
    ASSERT_EQ((void*)third, (void*)LIST_NEXT(LIST_NEXT(list)));
    ASSERT_EQ((void*)fourth, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(list))));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(LIST_NEXT(list)))));

    curr = list;
    LIST_CLEAR(&list) {
        ASSERT_EQ((void*)list, (void*)curr);
        curr = LIST_NEXT(curr);
        ++loops;
    }

    ASSERT_EQ(4, loops);
    return TEST_SUCCESS;
}

TEST_CASE(erase) {
    LIST(int) list = NULL;

    int *fourth = LIST_INSERT_NEW(&list, int);
    int *third = LIST_INSERT_NEW(&list, int);
    int *second = LIST_INSERT_NEW(&list, int);
    int *first = LIST_INSERT_NEW(&list, int);

    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ((void*)second, (void*)LIST_NEXT(list));
    ASSERT_EQ((void*)third, (void*)LIST_NEXT(LIST_NEXT(list)));
    ASSERT_EQ((void*)fourth, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(list))));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(LIST_NEXT(list)))));

    LIST_ERASE(LIST_LAST_PTR(&list));
    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ((void*)second, (void*)LIST_NEXT(list));
    ASSERT_EQ((void*)third, (void*)LIST_NEXT(LIST_NEXT(list)));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(LIST_NEXT(list))));

    LIST_ERASE(LIST_NEXT_PTR(list));
    ASSERT_EQ((void*)first, (void*)list);
    ASSERT_EQ((void*)third, (void*)LIST_NEXT(list));
    ASSERT_EQ(NULL, (void*)LIST_NEXT(LIST_NEXT(list)));

    LIST_ERASE(&list);
    ASSERT_EQ((void*)third, (void*)list);
    ASSERT_EQ(NULL, (void*)LIST_NEXT(list));

    LIST_CLEAR(&list);
    return TEST_SUCCESS;
}

int main() {
    TEST_SUITE(list_tests,
        TEST(next),
        TEST(next_ptr),
        TEST(new_buffer),
        TEST(new_element),
        TEST(insert),
        TEST(insert_new),
        TEST(foreach),
        TEST(foreach_ptr),
        TEST(last),
        TEST(last_ptr),
        TEST(end_ptr),
        TEST(append),
        TEST(append_new),
        TEST(size),
        TEST(clear),
        TEST(erase)
    );
    return 0;
}
