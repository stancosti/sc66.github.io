/**
 * @brief
 * @remarks
 * @version
 * @author
 * @copyright
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */
#ifndef __SOCKET_WEB_STATIC_H__
#define __SOCKET_WEB_STATIC_H__

#include "defines.h"
#include "metrics.h"
#include "logger.h"
#include "extern.h"

namespace sWS
{

/**
 * @remarks USE_STATIC_MESSAGE_HANDLER macro should be defined by the web client implementation.
 */
#ifdef USE_STATIC_MESSAGE_HANDLER

unsigned long nMsgSeq = 0;
unsigned long nBytesTotal = 0;
unsigned long tmElapsed = 0;
unsigned long tmElapsedTotal = 0;
const unsigned MESSAGE_BATCH_SIZE = 100;

/**
 * @brief This is a sample implementation of the static message handler. The library offers it to help improve the performance of onMessage function calls.
 * @remarks The performance of the static calls is higher than any regular member function call and even higher than a virtual member function call.
 */
inline void onMessage_static(char *message, const unsigned long length)
{
    //Count the number of message received
    ++nMsgSeq;

#if METRICS_LEVEL >= 0

    //Read time elapsed as difference between current time and loop iteration start time (?!)
    getTime<std::chrono::nanoseconds>(tmElapsed);

    //Sum-up the time spent for N number of messages
    tmElapsedTotal += tmElapsed;

    //Sum-up total number of bytes received
    nBytesTotal += length;

    //Print stats per message received
    // LOG_INFO("%9lu ________ %9lu bytes ________ %9lu ns", nMsgSeq, length, tmElapsed);
    // LOG_DEBUG("%9lu ________ %s", nMsgSeq, std::string(message, length).c_str());

    if (nMsgSeq % MESSAGE_BATCH_SIZE == 0)
    {
        // LOG_INFO("%lu => %s", nMsgSeq, std::string_view(message, length).data());
        LOG_INFO("%9lu ________ %9lu bytes ________ %9.2f ns", nMsgSeq, nBytesTotal, (tmElapsedTotal / (float)MESSAGE_BATCH_SIZE));
        nBytesTotal = 0;
        tmElapsedTotal = 0;
    }
#endif
}

#undef ON_MESSAGE_HANDLER
#define ON_MESSAGE_HANDLER(message, length) onMessage_static(message, length);

#else

#define ON_MESSAGE_HANDLER(message, length) onMessage(message, length);
#endif

} // namespace sWS

#endif