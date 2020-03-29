/**
 * @brief
 * @version
 * @date
 * @original https://github.com/dmcrodrigues/macro-logger
 * @copyright David Rodrigues
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
#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <string.h>

#define LOG_LEVEL_NONE 0x00
#define LOG_LEVEL_INFO 0x02
#define LOG_LEVEL_EVENT 0x03
#define LOG_LEVEL_DEBUG 0x04

#define LOG_FUNCTION(format, ...) fprintf(stderr, format, __VA_ARGS__)
#define NEWLINE "\n"

#if LOG_LEVEL >= LOG_LEVEL_INFO
#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define LOG_INFO_FMT "INFO   %12s:%3d | "
#define LOG_INFO(message, ...) LOG_FUNCTION(LOG_INFO_FMT message NEWLINE, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_INFO0(message) LOG_FUNCTION(LOG_INFO_FMT message NEWLINE, __FUNCTION__, __LINE__)
#else
#define LOG_INFO(message, ...) LOG_FUNCTION("INFO    " message NEWLINE, __VA_ARGS__)
#define LOG_INFO0(message) LOG_FUNCTION("INFO   %s", message NEWLINE)
#endif
#else
#define LOG_INFO(message, ...)
#define LOG_INFO0(message)
#endif

#if LOG_LEVEL >= LOG_LEVEL_EVENT
#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define LOG_EVENT_FMT "EVENT  %12s:%3d | "
#define LOG_EVENT(message, ...) LOG_FUNCTION(LOG_EVENT_FMT message NEWLINE, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_EVENT0(message) LOG_FUNCTION(LOG_EVENT_FMT message NEWLINE, __FUNCTION__, __LINE__)
#else
#define LOG_EVENT(message, ...) LOG_FUNCTION("EVENT  " message NEWLINE, __VA_ARGS__)
#define LOG_EVENT0(message) LOG_FUNCTION("EVENT  %s", message NEWLINE)
#endif
#else
#define LOG_EVENT(message, ...)
#define LOG_EVENT0(message)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define LOG_DEBUG_FMT "DEBUG  %12s:%3d | "
#define LOG_DEBUG_ARGS __FUNCTION__, __LINE__
#define LOG_DEBUG(message, ...) LOG_FUNCTION(LOG_DEBUG_FMT message NEWLINE, __FUNCTION__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG0(message) LOG_FUNCTION(LOG_DEBUG_FMT message NEWLINE, __FUNCTION__, __LINE__)
#else
#define LOG_DEBUG(message, ...)
#define LOG_DEBUG0(message)
#endif

#endif