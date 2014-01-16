#include <stdio.h>

#include "generic_list.h"
#include "utils.h"

typedef struct TestResult {
    const char *message;
    bool failed;
} TestResult;

typedef TestResult TestFunction(void);

typedef struct TestCase {
    const char *name;
    TestFunction *func;
} TestCase;

#define COLOR(text, color) "\033\[3" STR(color) ";1m" text "\033\[0m"
#define COLOR_RED(text) COLOR(text, 1)
#define COLOR_GREEN(text) COLOR(text, 2)
#define COLOR_YELLOW(text) COLOR(text, 3)

static const TestResult TEST_SUCCESS = { COLOR_GREEN("OK"), false };

static void runSuite(const char *name, TestCase *tests, size_t numTests) {
    size_t passed = 0;
    size_t failed = 0;
    size_t i = 0;

    printf(COLOR_YELLOW("suite %s\n"), name);
    for (i = 0; i < numTests; ++i) {
        TestResult result;
        
        printf("%-40s", tests[i].name);
        result = tests[i].func();
        printf("%s\n", result.message);

        if (result.failed) {
            ++failed;
        } else {
            ++passed;
        }
    }

    printf(COLOR_YELLOW("suite %s: %u passed, %u failed, %u total\n"), name, (unsigned)passed, (unsigned)failed, (unsigned)numTests);
}

#define ASSERT(expected, actual, operator) \
    do { \
        typeof(expected) expected__ = (expected); \
        typeof(actual) actual__ = (actual); \
        if (!(expected__ operator actual__)) { \
            TestResult ret = { COLOR_RED("FAILED\n") \
                               "*** at " COLOR_YELLOW(__FILE__ ":" STR(__LINE__)) " ***\n" \
                               COLOR_YELLOW("assertion: ") STR(expected) " " STR(operator) " " STR(actual), true }; \
            return ret; \
        } \
    } while (false)

#define ASSERT_EQ(expected, actual) ASSERT(expected, actual, ==)

#define TEST_SUITE(name, args...) \
    { \
        TestCase name[] = { args }; \
        runSuite(STR(name), name, ARRAY_SIZE(name)); \
    }

#define TEST(func) { STR(func), func }

#define TEST_CASE(name) static TestResult name(void)

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

int main() {
    TEST_SUITE(list_tests,
        TEST(next),
        TEST(next_ptr)
    );
    return 0;
}
