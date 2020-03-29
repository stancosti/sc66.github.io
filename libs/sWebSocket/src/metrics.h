/**
 * @brief
 * @remarks
 * @version
 * @author
 * @copyright
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
#ifndef __GLOBAL_METRICS_H__
#define __GLOBAL_METRICS_H__

#include <chrono>
#include <string>

#ifdef USE_METRICS

std::chrono::high_resolution_clock::time_point tmStats;

/**
 * @brief
 * @remarks
 */
inline void startTimer()
{
    tmStats = std::chrono::high_resolution_clock::now();
}

/**
 * @brief
 * @remarks
 */
template <typename T>
inline void getTime(unsigned long &elapsed)
{
    elapsed = std::chrono::duration_cast<T>(std::chrono::high_resolution_clock::now() - tmStats).count();
}

#else

/**
 * @brief
 * @remarks
 */
inline void startTimer()
{
}

/**
 * @brief
 * @remarks
 */
template <typename T>
inline void getTime(unsigned long &elapsed)
{
}

#endif

#ifdef OVERRIDE_GLOBAL_ALLOC

/**
 * Global operator new overload. Therefore, we can see which operation causes a memory allocation.
 */
void *operator new(std::size_t count)
{
    printf("new (%lu)\n", count);
    return malloc(count);
}

void operator delete(void *p)_GLIBCXX_USE_NOEXCEPT
{
    printf("free(%lu)\n", sizeof(p));
    free(p);
}

void operator delete(void *p, std::size_t s)
{
    printf("free(%lu)\n", s);
    free(p);
}

#endif

#endif