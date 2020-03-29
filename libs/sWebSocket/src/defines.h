/**
 * @brief
 * @version
 * @date
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */
#ifndef __DEFINES_H__
#define __DEFINES_H__

/**
 * Enable compression handling at the http channel level.
 *
 *
#define USE_COMPRESSION

/**
 * Enable decompression of http messages.
 *
 *
#define CHK_COMPRESSION_ON_MESSAGE

/**
 * Enable check for UTF8 correctness at the message level.
 *
 *
#define CHK_UTF8_MESSAGE

/**
 * Enable check for control bits.
 *
 *
#define CHK_MSG_CTRL_BITS

/**
 * Enforces thread-safe operations (very basic)
 *
 *
#define THREAD_SAFE

/**
 * Socket based metrics. Must include "metrics.h".
 */
#define USE_METRICS

/**
 * Time based _metrics.
 */
#define METRICS_LEVEL 4

/**
 * Macro-Logger
 * Levels:  NONE, INFO, EVENT, DEBUG
 */
#define LOG_LEVEL LOG_LEVEL_EVENT

/**
 * Overwrite the global memory allocators (e.g. new, delete)
 */
// #define OVERRIDE_GLOBAL_ALLOC

#endif