#ifndef MIKRO_PROJEKT_TEST_H
#define MIKRO_PROJEKT_TEST_H

#include "utils.h"

#include <stddef.h>
#include <stdio.h>


typedef struct TestResult {
    const char *message;
    bool failed;
} TestResult;

typedef TestResult TestFunction(void);

typedef struct TestCase {
    const char *name;
    TestFunction *func;
} TestCase;

#define COLOR(text, color) "\033[3" STR(color) ";1m" text "\033[0m"
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

    printf(COLOR_YELLOW("suite %s: ") COLOR_GREEN("%u passed") ", " COLOR_RED("%u failed") ", %u total\n", name, (unsigned)passed, (unsigned)failed, (unsigned)numTests);
}

#define ASSERT(expected, actual, operator) \
    do { \
        typeof(expected) expected__ = (expected); \
        typeof(actual) actual__ = (actual); \
        if (!(expected__ operator actual__)) { \
            TestResult ret = { COLOR_RED("FAILED\n") \
                               "at " COLOR_YELLOW(__FILE__ ":" STR(__LINE__)), true }; \
            return ret; \
        } \
    } while (false)

#define ASSERT_EQ(expected, actual) ASSERT(expected, actual, ==)
#define ASSERT_NEQ(expected, actual) ASSERT(expected, actual, !=)

#define TEST_SUITE(name, args...) \
    { \
        TestCase name[] = { args }; \
        runSuite(STR(name), name, ARRAY_SIZE(name)); \
    }

#define TEST(func) { STR(func), func }

#define TEST_CASE(name) static TestResult name(void)

#endif /* MIKRO_PROJEKT_TEST_H */
