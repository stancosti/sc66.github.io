/**
 * @brief
 * @hints: there are on average 36-50 bugs per thousand lines of code! NASA holds the world record with 0 bugs in 500 thousand lines. Each line of code costs about $2000.
 * @remarks the underlying protocol implementation is based on version 0.14 of the uWebSockets library.
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
#ifndef __WEB_CLIENT_H__
#define __WEB_CLIENT_H__

#define USE_STATIC_MESSAGE_HANDLER

#include "defines.h"
#include "metrics.h"
#include "web_session.h"
#include "socket_web_static.h" // @remarks include "global_handlers.h" only if you prefer the onMessage events to be handled by a static function instead of the member function.
#include "socket_web.h"

namespace sWS
{

class WebClient : protected sWS::WebSocket
{
    const unsigned MESSAGE_BATCH_SIZE = 100;
    const unsigned READ_MAX_ERRORS = 7;
    const unsigned TIMEOUT_CNT_MAX = 11;
    unsigned long nMsgSeq = 0;
    unsigned long nBytesTotal = 0;
    unsigned long tmElapsed = 0;
    unsigned long tmElapsedTotal = 0;
    sWS::WebSession _session;

public:
    WebClient() : WebSocket(0, false), _session()
    {
        //  Create a new SSL structure which is needed to hold the data for a TLS/SSL connection. The new structure inherits the settings of the underlying context.
        WebSocket::init(_session.new_ssl_context());
    }

    WebClient(sWS::WebSession &session) : WebSocket(0, false), _session(session)
    {
        //  Create a new SSL structure which is needed to hold the data for a TLS/SSL connection. The new structure inherits the settings of the underlying context.
        WebSocket::init(_session.new_ssl_context());
    }

    ~WebClient()
    {
        _session.release(WebSocket::_ssl_ptr);
        _session.~WebSession();
    }

    bool subscribe(const char *aServiceURI, const char *aSubscribeRequest, uint aTimeout = 5000, uint aRetryMax = 5, uint aRetryInterval = 5000)
    {
        if (WebSocket::isConnected())
        {
            throw std::logic_error("Client is already connected or in the process of disconnecting.");
        }

        std::string hostname, port, path;
        uint nConnectCount = 0;
        int nTimeouts = 0;
        bool secure;

        if (!_session.parse_uri(aServiceURI, secure, hostname, port, path))
        {
            onError("Cannot parse the service URI.", 0, ErrorCode::CONNECT);
            return false;
        }

        if (!secure)
        {
            onError("Cannot subscribe to an unsecured endpoint.", 0, ErrorCode::CONNECT);
            return false;
        }

    reconnect:

        if (nConnectCount == 0)
        {
            //  Attempt initial connection
            LOG_EVENT("Subscribe (%s timeout seeting %d)", aServiceURI, aTimeout);
        }
        else if (nConnectCount > aRetryMax)
        {
            //LOG_ERROR("Failed to connect after %d attempts", aRetryMax);

            //  Stop any further attempts
            WebSocket::close("cannot reconnect.");
            return false;
        }
        else
        {
            //  Close previous connection (if any)
            WebSocket::close("reconnecting..");

            //  Attempt to reconnect
            LOG_EVENT("Subscribe (attempt %d out of %d, retry every %d ms)", nConnectCount, aRetryMax, aRetryInterval);
            std::this_thread::sleep_for(std::chrono::milliseconds(aRetryInterval));
        }

        //  Increment the number of connection attempts; will reset it once a connection has been established
        nConnectCount++;

        //  Create a new connection, will upgrade it to a WebSocket as soon as a connection has been established
        if (!WebSocket::connect(hostname.c_str(), port.c_str(), path.c_str(), aTimeout))
        {
            goto reconnect;
        }

        //  Send subscribe request
        WebSocket::request(aSubscribeRequest);
        LOG_EVENT("Subscribed (%s)", aSubscribeRequest);

        //  Reset (re)connect counters
        nConnectCount = 1;

#ifdef __GLOBAL_HANDLERS_H__
        LOG_INFO0("Stream (using global message handler)");
#endif

        //  Read market feed as a stream of messages (block waiting)
        int nReadResult = WebSocket::read_stream(nTimeouts, READ_MAX_ERRORS);

        switch (nReadResult)
        {
        case 0:
            //done reading
            WebSocket::close("session ended");
            return true;
        case -1:
            //closed already
            return false;
        case -2:
            //shutting-down
            WebSocket::close("shutdown requested");
            return false;
        case -3:
            //max subsequent errors reached
            WebSocket::close("subsequent read errors");
            return true;
        case -4:
            //shutdown requested by client on timeout
            WebSocket::close("shutdown due to timeouts");
            return false;
        default:
            LOG_EVENT("Subscribe (%d reconnect)", nConnectCount);
            goto reconnect;
            break;
        }

        //  Graceful exit. Done!
        return true;
    }

protected:
    void onConnect(const char *aURI) override
    {
        LOG_EVENT("Connected (%s)", aURI);
        nMsgSeq = 0;
    }

    void onDisconnect(const char *message, size_t length, const int code) override
    {
        LOG_EVENT("Disconnected (%s)", message);
    }

    void onTimeout(int &code) override
    {
        LOG_EVENT("Timeout (%d).", code);

        if (code > (int)TIMEOUT_CNT_MAX)
        {
            // Signal disconnect after timeouts limit has been reached
            code = -1;
        }
    }

    void onError(const char *message, size_t length, const ErrorCode code) override
    {
        LOG_EVENT("Web error (%d): %s", (int)code, (char *)message);
    }

    inline void onMessage(const char *message, size_t length) override
    {
        LOG_EVENT("%s", message);
    }
};

} // namespace sWS

#endif // WEB_CLIENT_H