/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TONGSUOMINI_TEST_H)
# define TONGSUOMINI_TEST_H
# pragma once

# include "internal/asn1.h"
# include <stdio.h>
# include <stdlib.h>

# define TEST(...) RUN_TEST(__VA_ARGS__, __FILE__, __LINE__)
# define RUN_TEST(func, file, line)                                                                \
  do {                                                                                             \
   int ret = func();                                                                               \
   if (ret) {                                                                                      \
    fprintf(stderr, "Failed\t%s\t%s:%d\n", #func, file, line);                                     \
    return ret;                                                                                    \
   } else {                                                                                        \
    fprintf(stderr, "Passed\t%s\t%s:%d\n", #func, file, line);                                     \
   }                                                                                               \
  } while (0)

# define ASSERT(exp)     TEST_ASSERT((exp), __FUNCTION__, __LINE__)
# define ASSERT_OK(ret)  TEST_ASSERT(((ret) == 0), __FUNCTION__, __LINE__)
# define ASSERT_ERR(ret) TEST_ASSERT(((ret) != 0), __FUNCTION__, __LINE__)

# define TEST_ASSERT(exp, func, line)                                                              \
  do {                                                                                             \
   if (exp) {                                                                                      \
    ;                                                                                              \
   } else {                                                                                        \
    TEST_FAIL((func), (line));                                                                     \
   }                                                                                               \
  } while (0)

static inline void TEST_FAIL(const char *func, int line)
{
    fprintf(stderr, "Assert Failed\t%s:%d\n", func, line);
    exit(1);
}

#endif