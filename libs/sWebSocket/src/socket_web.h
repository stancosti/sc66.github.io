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
#ifndef __SOCKET_WEB_H__
#define __SOCKET_WEB_H__

#include "socket.h"
#include "socket_http.h"
#include "logger.h"
#include "extern.h"

namespace sWS
{

/**
 * @remarks Unless specified, the default message handler is the virtual member function.
 */
#ifndef ON_MESSAGE_HANDLER
#define ON_MESSAGE_HANDLER(message, length) onMessage(message, length);
#endif

/**
 * @brief High-level ("single connection", "blocking mode", "specialized streamming") client based on a "customized" implementation of the WebSocket protocol.
 * @remarks 1. It's specialized to read a single stream of data with an average payload  of 120 - 256 bytes.
 * @remarks 2. It's not expected to have outbound communication after the initial WebSocket upgrade request. For your convenience, some minimal functionality is provided by the SendPrepared() member function.
 */
struct WebSocket
{
protected:
    static const unsigned LARGE_BUFFER_SIZE = 1024 * 2; //determined based on stream analysis, increase or decrease until there is very litle fragmentation
    static const unsigned SHORT_MESSAGE_HEADER = 2;
    static const unsigned MEDIUM_MESSAGE_HEADER = 4;
    static const unsigned LONG_MESSAGE_HEADER = 10;
    static const unsigned CONSUME_POST_PADDING = 4;
    static const unsigned CONSUME_PRE_PADDING = LONG_MESSAGE_HEADER - 1;

    SSL *_ssl_ptr = nullptr;
    sWS::Socket _socket_raw;

    bool _consume_msg_fin;
    size_t _content_length = 0;
    size_t _remaining_bytes = 0;
    unsigned char _consume_payload_len = 0;
    unsigned char _control_tip_len = 0;
    unsigned char _cOpCode;

    std::string _rx_fragment;             //received fragment (dynamic?!)
    char _rx_buffer[LARGE_BUFFER_SIZE];   //receive buffer on stack
    const size_t _tx_buffer_blocks = 100; //output message blocks (pre-allocated)
    char **_tx_buffer;                    //buffer for sent bytes (heap allocations)

    enum ErrorCode : int
    {
        UNKNOWN = -10000,
        CONNECT = -10001,
        NETWORK = -10002,
        PARSER = -10003,
        READ = -10004,
        WRITE = -10005,
        PROTO = -10006
    };

    enum OpCode : unsigned char
    {
        TEXT = 1,
        BINARY = 2,
        CLOSE = 8,
        PING = 9,
        PONG = 10
    };

    struct CloseFrame
    {
        uint16_t code;
        char *message;
        size_t length;
    };

    struct WsState
    {
        // 16 bytes ???
        unsigned wantsHead : 1;
        unsigned spillLength : 4;
        unsigned lastFin : 1;
        int opStack : 2; // -1, 0, 1

        // 15 bytes
        unsigned char spill[LONG_MESSAGE_HEADER - 1];
        OpCode opCode[2];

        WsState()
        {
            wantsHead = true;
            spillLength = 0;
            opStack = -1;
            lastFin = true;
            opCode[0] = OpCode::TEXT;
            memset(spill, 0, sizeof(spill));
        }

    } _wsState;

    struct TxQueue
    {
        struct Message
        {
            const char *data;
            size_t length;
            Message *nextMessage = nullptr;
            void (*callback)(void *socket, void *data, bool cancelled, void *reserved) = nullptr;
            void *callbackData = nullptr, *reserved = nullptr;
        };

        Message *head = nullptr, *tail = nullptr;

        bool empty() { return head == nullptr; }
        Message *front() { return head; }

        inline void pop()
        {
            Message *nextMessage;
            if ((nextMessage = head->nextMessage))
            {
                delete[](char *) head;
                head = nextMessage;
            }
            else
            {
                delete[](char *) head;
                head = tail = nullptr;
            }
        }

        inline void push(Message *message)
        {
            message->nextMessage = nullptr;
            if (tail)
            {
                tail->nextMessage = message;
                tail = message;
            }
            else
            {
                head = message;
                tail = message;
            }
        }

        static void freeMessage(TxQueue::Message *message)
        {
            delete[](char *) message;
        }

        static TxQueue::Message *alloc(size_t length, const char *data = 0)
        {
            TxQueue::Message *messagePtr = (TxQueue::Message *)new char[sizeof(TxQueue::Message) + length];
            messagePtr->length = length;
            messagePtr->data = ((char *)messagePtr) + sizeof(TxQueue::Message);
            messagePtr->nextMessage = nullptr;

            if (data)
            {
                memcpy((char *)messagePtr->data, data, messagePtr->length);
            }

            return messagePtr;
        }
    } _messageQueue;

    enum Options : unsigned
    {
        NO_OPTIONS = 0,
        NO_DELAY = 8,
#ifdef USE_COMPRESSION
        PERMESSAGE_DEFLATE = 1,
        SLIDING_DEFLATE_WINDOW = 16
#endif
    };
    const unsigned _ext_options = 0;

#ifdef THREAD_SAFE
    std::recursive_mutex _mux{};
#endif

#ifdef USE_COMPRESSION
    static const size_t zxBufferSize = LARGE_BUFFER_SIZE * 256; //original: 16777216
    z_stream inflationStream = {};
    z_stream deflationStream = {};
    std::string zxBufferStr;
    char *zxBuffer;

    enum CompressionStatus : char
    {
        DISABLED,
        ENABLED,
        COMPRESSED_FRAME
    } _compressionStatus;
    void *_slidingDeflateWindow = nullptr;

#else
    enum CompressionStatus : char
    {
        DISABLED
    } _compressionStatus;
#endif

public:
    /**
     * @remarks Disable unwanted copying construction
     */
    WebSocket(const WebSocket &) = delete;

    /**
     * @remarks Disable unwanted copying assignment
     */
    WebSocket &operator=(const WebSocket &copy) = delete;

    /**
     * @brief Web Socket constructor
     * @param aExtOptions
     * @param perMessageDeflate
     * @param aPrePadding
     * @param aPostPadding
     */
    WebSocket(const unsigned aExtOptions = 0,
              const bool perMessageDeflate = false,
              const unsigned aPrePadding = CONSUME_PRE_PADDING,
              const unsigned aPostPadding = CONSUME_POST_PADDING)
        : _socket_raw(),
          _ext_options(aExtOptions)
    {
        //  Init buffers
        memset(_rx_buffer, 0, strlen(_rx_buffer));

        int nBlocks = getBlockSize(_tx_buffer_blocks) + 1;
        _tx_buffer = new char *[nBlocks];
        for (int i = 0; i < nBlocks; ++i)
        {
            _tx_buffer[i] = nullptr;
        }

        // optimize string allocations by setting the capacity of the fragment buffer to match at least the receive buffer size
        _rx_fragment.reserve(strlen(_rx_buffer));
        _compressionStatus = CompressionStatus::DISABLED;

#ifdef USE_COMPRESSION
        _compressionStatus = perMessageDeflate ? CompressionStatus::ENABLED : CompressionStatus::DISABLED;
        if (session->_slidingDeflateWindow())
        {
            // allocate if we are in a session with sliding deflate window
            _slidingDeflateWindow = allocateDefaultCompressor(new z_stream{});
        }

        if (perMessageDeflate)
        {
            std::__throw_logic_error("Compression has been disabled.");
        }

        inflateInit2(&inflationStream, -15);
        zxBuffer = new char[LARGE_BUFFER_SIZE];
        allocateDefaultCompressor(&deflationStream);
#else
        if (perMessageDeflate)
        {
            throw new std::logic_error("Compression has been disabled. Please recompile the library with the USE_COMPRESSION switch.");
        }
#endif
    }

    /**
     * @brief Destroy the WebSocket object
     */
    virtual ~WebSocket()
    {
        if (!_socket_raw.isClosed() && !_socket_raw.isShuttingDown())
        {
            close("web client destruction");
        }

        //  Reset receive buffers
        memset(_rx_buffer, 0, LARGE_BUFFER_SIZE);
        _rx_fragment.clear();

        //  Release allocated transmission blocks
        int nLength = getBlockSize(_tx_buffer_blocks) + 1;
        for (int i = 0; i < nLength; i++)
        {
            if (_tx_buffer[i])
            {
                delete[] _tx_buffer[i];
            }
        }
        delete[] _tx_buffer;

#ifdef USE_COMPRESSION
        //  Dispose of zlib resource streams
        // remove any per-websocket zlib memory, as it relates to WebClient::allocateDefaultCompressor
        if (_slidingDeflateWindow)
        {
            deflateEnd((z_stream *)_slidingDeflateWindow);
            delete (z_stream *)_slidingDeflateWindow;
            _slidingDeflateWindow = nullptr;
        }

        //free resources used by zLib
        inflateEnd(&inflationStream);
        deflateEnd(&deflationStream);
        delete[] zxBuffer;
#endif
    }

    /**
     * @brief
     * @param aSslCtx SSL structure which is needed to hold the data for a TLS/SSL connection. This inherits the settings of the global SSL context.
     */
    void init(SSL *aSslCtx)
    {
        _ssl_ptr = aSslCtx;
    }

    /**
     * @brief Checks if the underlying socket is not closed nor in process of shutting down.
     * @return State of the underlying socket
     */
    inline bool isConnected() const
    {
        return !_socket_raw.isClosed() && !_socket_raw.isShuttingDown();
    }

    /**
     * @brief Checks if the underlying socket is in process of shutting down.
     * @return Shutting-down state of the underlying socket
     */
    inline bool isShuttingDown() const
    {
        return _socket_raw.isShuttingDown();
    }

    /**
     * @brief Establish a new connection.vd
     * @param hostname
     * @param port
     * @param secure
     * @param path
     * @param aReadTimeout
     * @param aSendTimeout
     * @return State of the underlying socket
     */
    bool connect(const char *hostname, const char *port, const char *path, const unsigned aReadTimeout = 5000, const unsigned aSendTimeout = 5000)
    {
#ifdef THREAD_SAFE
        std::lock_guard<std::recursive_mutex> lockGuard(_mux);
#endif

        if (isConnected())
        {
            onError("Connection already established.", 0, ErrorCode::CONNECT);
            return false;
        }
        else if (!_ssl_ptr)
        {
            LOG_DEBUG0("->missing SSL context");
            throw new std::logic_error("Missing SSL context information. This implementation supports only secured connections.");
        }

        try
        {
            //  Set client's ssl context in connect mode and associate it with the provided host
            SSL_set_tlsext_host_name(_ssl_ptr, hostname);
            SSL_set_connect_state(_ssl_ptr);

            //  Establish connectivity
            _socket_raw.connect(hostname, port, _ssl_ptr, aReadTimeout);

            //  Set additional socket properties
            _socket_raw.setNoDelay(true);
        }
        catch (const std::runtime_error &e)
        {
            LOG_DEBUG("->failed to connect, %s (%s:%s)", e.what(), hostname, port);
            onError("Cannot establish connection.", 0, ErrorCode::NETWORK);
            return false;
        }
        catch (const std::exception &e)
        {
            LOG_DEBUG("->failed to connect, %s (%s:%s)", e.what(), hostname, port);
            onError("Cannot establish connection.", 0, ErrorCode::CONNECT);
            return false;
        }

        //  Request upgrade to WebSocket
        auto bUpgraded = upgrade(path, hostname, port);

        if (!bUpgraded)
        {
            LOG_DEBUG0("->failed to upgrade to http socket.");
            onError("Cannot setup the websocket connection.", 0, ErrorCode::CONNECT);
            return false;
        }

        LOG_DEBUG0("->websocket connected.");
        return true;
    }

public:
    /**
     * @brief Send disconnect code to the server, release the client connection, then notify the web client.
     * @param reason
     * @hints: Close code will be 1006 and message will be what you pass as reason.
     */
    void close(const char *reason)
    {
        close(reason, 1006, reason, strlen(reason));
    }

    /**
     * @brief Begins a passive WebSocket closedown handshake (might succeed or not), then calls the disconnect handler and release socket resources.
     * @param reason
     * @param code
     * @param message
     * @param length
     */
    void close(const char *reason, const int code, const char *message = nullptr, size_t length = 0)
    {

#ifdef THREAD_SAFE
        std::lock_guard<std::recursive_mutex> lockGuard(_mux);
#endif

        if (_socket_raw.isShuttingDown() || _socket_raw.isClosed())
        {
            return;
        }
        else
        {
            if ((code != 0))
            {
                LOG_DEBUG("->websocket closing: %d", code);

                //  Close the downlink, keep uplink open long enough to send a single message
                _socket_raw.shutdown(true, false);

                //  Send CLOSE request (no handshake expected, doesn't require acknowledgement from the server)
                static const int MAX_CLOSE_PAYLOAD = 123;
                char closePayload[MAX_CLOSE_PAYLOAD + 2];
                int closePayloadLength = (int)WebSocket::formatClosePayload(closePayload, code, message, length);
                length = std::min<size_t>(MAX_CLOSE_PAYLOAD, length);

                // send message asynchronously and don't wait for a reply!
                send(closePayload, closePayloadLength, OpCode::CLOSE, [](WebSocket *p, void *data, bool cancelled, void *reserved) {
                    // if (!cancelled), expecting the server to respond with a cancellation?!
                });
            }

            //  Close the connection and release its resources
            _socket_raw.close(reason);

            //  Dispose of queued messages
            LOG_DEBUG0("->release send queue");
            while (!_messageQueue.empty())
            {
                //  empty the output queue
                TxQueue::Message *message = _messageQueue.front();
                if (message->callback)
                {
                    message->callback(nullptr, message->callbackData, true, nullptr);
                }
                _messageQueue.pop();
            }

            onDisconnect(reason, strlen(reason), code);

            LOG_DEBUG0("->websocket closed.");
        }
    }

public:
    int read_stream(int &aRetries, const char aMaxErrors = 5)
    {
        aRetries = 0;

#if METRICS_LEVEL >= 1
        //  Set inititial timer
        //  Will help compute the total time spent receiving messages
        startTimer();
#endif

        int nSSLRead;
        size_t nRxBytes;
        char *pRxData;

        do
        {

#if METRICS_LEVEL == 2
            //  Time-based stats: how long does it take to receive and process a complete message?
            startTimer();
#endif
            do
            {
            readNext:

#if METRICS_LEVEL == 3
                //  Time only the last read for each message, most of the messages are received and decrypted in one pass.
                //  This measurement will factor the interval in between two consecutive reads.
                startTimer();
#endif
                // nSSLRead = SSL_peek(_ssl_ptr, _rx_buffer, LARGE_BUFFER_SIZE - 1);

                //  Read continuously (blocking mode)
                nSSLRead = SSL_read(_ssl_ptr, _rx_buffer, LARGE_BUFFER_SIZE - 1);
                if (nSSLRead > 0)
                {

#if METRICS_LEVEL == 4
                    //  Processing start time for each received batch/message/fragments, after they have been decrypted
                    startTimer();
#endif

                    // ON_MESSAGE_HANDLER(_rx_buffer, nSSLRead);
                    // goto readNext;

                    //  Reset the timeout counter when data is received
                    aRetries = 0;

                    //  __BEGIN_CONSUME_MESSAGE__ process rx buffer (complete message or fragments)
                    pRxData = _rx_buffer;
                    nRxBytes = nSSLRead;
                    LOG_DEBUG("rcvd: %lu bytes", nRxBytes);

                    if (_wsState.spillLength)
                    {
                        LOG_DEBUG("spil: %du", _wsState.spillLength);
                        pRxData -= _wsState.spillLength;
                        nRxBytes += _wsState.spillLength;
                        memcpy(pRxData, _wsState.spill, _wsState.spillLength);
                    }

                    if (_wsState.wantsHead)
                    {
                    consumeNext:
                        LOG_DEBUG("next: %lu bytes", nRxBytes);

                        while (nRxBytes >= SHORT_MESSAGE_HEADER)
                        {
                            payloadLength(pRxData, _consume_payload_len);

#ifdef CHK_MSG_CTRL_BITS
                            getOpCode(pRxData, _cOpCode);
                            if ((rsv1(pRxData) && !setCompressed()) || rsv23(pRxData) || (_cOpCode > 2 && _cOpCode < 8) || (_cOpCode > 10) || (_cOpCode > 2 && (!isFin(pRxData) || _consume_payload_len > 125)))
                            {
                                // invalid reserved bits / invalid opcodes / invalid control frames / set compressed frame
                                LOG_DEBUG("c0  : %d invalid", _consume_payload_len);
                                close("invalid message properties (e.g. reserved bits, opcode, control frame, compression)");
                                return -5;
                            }
#endif

                            if (_consume_payload_len < 126)
                            {
                                if (read<SHORT_MESSAGE_HEADER, uint8_t>(_consume_payload_len, pRxData, nRxBytes))
                                {
                                    LOG_DEBUG("c1  : %d next", _consume_payload_len);
                                    goto readNext;
                                }
                            }
                            else if (_consume_payload_len == 126)
                            {
                                if (nRxBytes < MEDIUM_MESSAGE_HEADER)
                                {
                                    LOG_DEBUG("c2  : %d break", _consume_payload_len);
                                    break;
                                }
                                else if (read<MEDIUM_MESSAGE_HEADER, uint16_t>(ntohs(*(uint16_t *)&pRxData[2]), pRxData, nRxBytes))
                                {
                                    LOG_DEBUG("c2  : %lu not consumed", nRxBytes);
                                    goto readNext;
                                }
                            }
                            else if (nRxBytes < LONG_MESSAGE_HEADER)
                            {
                                LOG_DEBUG("c3  : %d break", _consume_payload_len);
                                break;
                            }
                            else if (read<LONG_MESSAGE_HEADER, uint64_t>(be64toh(*(uint64_t *)&pRxData[2]), pRxData, nRxBytes))
                            {
                                LOG_DEBUG("c4  : %d next", _consume_payload_len);
                                goto readNext;
                            }
                            else
                            {
                                LOG_DEBUG("c4  : %lu not consumed", nRxBytes);
                            }
                        }

                        if (nRxBytes)
                        {
                            //  spilled data
                            LOG_DEBUG("c5  : %lu spilled", nRxBytes);
                            memcpy(_wsState.spill, pRxData, nRxBytes);
                            _wsState.spillLength = nRxBytes;
                        }
                    }
                    else if (_remaining_bytes <= nRxBytes)
                    {
                        LOG_DEBUG("c6: %8lu bytes, remaining %lu", nRxBytes, _remaining_bytes);
                        if (!read_fragm(pRxData, _remaining_bytes, 0, _wsState.opCode[_wsState.opStack], _wsState.lastFin))
                        {
                            if (_wsState.lastFin)
                            {
                                _wsState.opStack--;
                            }

                            pRxData += _remaining_bytes;
                            nRxBytes -= _remaining_bytes;
                            _wsState.wantsHead = true;
                            goto consumeNext;
                        }
                    }
                    else
                    {
                        LOG_DEBUG("c7: %8lu bytes, remaining %lu", nRxBytes, _remaining_bytes);
                        _remaining_bytes -= nRxBytes;
                        read_fragm(pRxData, nRxBytes, _remaining_bytes, _wsState.opCode[_wsState.opStack], _wsState.lastFin);
                        //consumed, do not allow further message processing?!
                    }

                    //  __END_CONSUME_MESSAGE__
                }
                else if (_socket_raw.isClosed())
                {
                    LOG_DEBUG0("->web-read: error after socket closed");
                    return -1;
                }
                else if (_socket_raw.isShuttingDown())
                {
                    LOG_DEBUG0("->web-read: error during shutdown");
                    return -2;
                }
                else
                {
                    if (++aRetries > aMaxErrors)
                    {
                        LOG_DEBUG("->web-read: %d subsequent read errors.", aRetries);
                        onError("Reached the maximum number of subsequent read errors.", 0, ErrorCode::READ);
                        return -3;
                    }

                    switch (SSL_get_error(_ssl_ptr, nSSLRead))
                    {
                    case SSL_ERROR_WANT_READ:

                        //  Notify client on read timeout and let them decide to disconnect, reconnect or just continue
                        LOG_DEBUG0("->web-read: SSL_ERROR_WANT_READ");
                        LOG_DEBUG("->web-timeout after %d attempts", aRetries);
                        onTimeout((int &)aRetries);

                        if (aRetries < 0)
                        {
                            LOG_DEBUG0("->web-read: close requested by client on timeout.");
                            return -4;
                        }
                        break;

                    case SSL_ERROR_WANT_WRITE:

                        LOG_DEBUG0("->web-read-error: SSL_ERROR_WANT_WRITE");
                        onError("Failed to read message (SSL_ERROR_WANT_WRITE).", 0, ErrorCode::READ);
                        break;

                    case SSL_ERROR_SYSCALL:

                        LOG_DEBUG0("->web-read-error: SSL_ERROR_SYSCALL");
                        onError("Failed to read message (SSL_ERROR_SYSCALL).", 0, ErrorCode::READ);
                        break;

                    default:

                        LOG_DEBUG0("->web-read-error: SSL_ERROR");
                        onError("Failed to read message (SSL other).", 0, ErrorCode::READ);
                        break;
                    }
                }

            } while (SSL_pending(_ssl_ptr));

        } while (!_socket_raw.isShuttingDown());

        //  Report success
        return 0;
    }

public:
    /**
    * @brief Request data.
    * @param message
    * @param opCode
    * @remarks Thread safe
    */
    void request(const char *message, OpCode opCode = OpCode::TEXT)
    {
        send(message, strlen(message), opCode);
    }

protected:
    /**
    * @brief Frames and sends a WebSocket message.
    * @hints: Consider using any of the prepare function if any of their use cases match what you are trying to achieve (pub/sub, broadcast)
    * @remarks Thread safe
    */
    void send(const char *message, size_t length, OpCode opCode, void (*callback)(WebSocket *webSocket, void *data, bool cancelled, void *reserved) = nullptr, void *callbackData = nullptr, bool compress = false)
    {

#ifdef THREAD_SAFE
        std::lock_guard<std::recursive_mutex> lockGuard(_mux);
        if (_socket_raw.isShuttingDown() || _socket_raw.isClosed())
        {
            if (callback)
            {
                callback(this, callbackData, true, nullptr);
            }
            return;
        }
#endif

        const int HEADER_LENGTH = LONG_MESSAGE_HEADER;

#ifdef USE_COMPRESSION
        struct TransformData
        {
            WebSocket *s;
            OpCode opCode;
            bool compress;
        } transformData = {this, opCode, compress && _compressionStatus == WebSocket::CompressionStatus::ENABLED && opCode < 3};
#else
        struct TransformData
        {
            WebSocket *s;
            OpCode opCode;
        } transformData = {this, opCode};
#endif

        struct WebSocketTransformer
        {
            static size_t estimate(const char *data, size_t length)
            {
                return length + HEADER_LENGTH;
            }

            static size_t transform(const char *src, char *dst, size_t length, TransformData transformData)
            {

#ifdef USE_COMPRESSION
                if (transformData.compress)
                {
                    char *deflated = transformData.s->session->deflate((char *)src, length, (z_stream *)transformData.s->_slidingDeflateWindow);
                    return WebSocket::formatMessage(dst, deflated, length, transformData.opCode, length, true);
                }
#endif

                return WebSocket::formatMessage(dst, src, length, transformData.opCode, length, false);
            }
        };

        sendTransformed<WebSocketTransformer>((char *)message, length, transformData, (void (*)(void *, void *, bool, void *))callback, callbackData);
    }

protected:
    /**
     * @brief
     * @param
     * @param
     * @param
     * @param
     * @remarks
     */
    bool sendMessage(TxQueue::Message *message)
    {
        try
        {
            static int nSent;
            return _socket_raw.send(message->data, message->length, nSent, _ssl_ptr);
        }
        catch (const std::runtime_error &e)
        {
            //  Notify client on errors
            onError(e.what(), 0, ErrorCode::WRITE);
            return false;
        }
    }

    /**
     * @brief
     * @param
     * @param
     * @param
     * @param
     * @remarks
     */
    template <class T, class DT>
    void sendTransformed(const char *message, size_t length, DT dataTransformer, void (*callback)(void *socket, void *data, bool cancelled, void *reserved), void *callbackData)
    {
        size_t estLen = T::estimate(message, length) + sizeof(TxQueue::Message);

        if (_messageQueue.empty())
        {
            if (estLen <= _tx_buffer_blocks)
            {
                auto msgLen = getBlockSize(estLen);

                TxQueue::Message *messagePtr = (TxQueue::Message *)getBlockSmall(msgLen);
                messagePtr->data = ((char *)messagePtr) + sizeof(TxQueue::Message);
                messagePtr->length = T::transform(message, (char *)messagePtr->data, length, dataTransformer);

                if (sendMessage(messagePtr))
                {
                    messagePtr->callback = callback;
                    messagePtr->callbackData = callbackData;
                }
                else
                {
                    freeBlockSmall((char *)messagePtr, msgLen);
                    if (callback)
                    {
                        callback(this, callbackData, true, nullptr);
                    }
                }
            }
            else
            {
                TxQueue::Message *messagePtr = TxQueue::alloc(estLen - sizeof(TxQueue::Message));
                messagePtr->length = T::transform(message, (char *)messagePtr->data, length, dataTransformer);

                if (sendMessage(messagePtr))
                {
                    messagePtr->callback = callback;
                    messagePtr->callbackData = callbackData;
                }
                else
                {
                    TxQueue::freeMessage(messagePtr);
                    if (callback)
                    {
                        callback(this, callbackData, true, nullptr);
                    }
                }
            }
        }
        else
        {
            TxQueue::Message *messagePtr = TxQueue::alloc(estLen - sizeof(TxQueue::Message));
            messagePtr->length = T::transform(message, (char *)messagePtr->data, length, dataTransformer);
            messagePtr->callback = callback;
            messagePtr->callbackData = callbackData;
            _messageQueue.push(messagePtr);
        }
    }

protected:
    bool setCompressed()
    {

#ifndef USE_COMPRESSION
        return false; //Compression has been disabled
#else
        if (_compressionStatus == WebSocket::CompressionStatus::ENABLED)
        {
            _compressionStatus = WebSocket::CompressionStatus::COMPRESSED_FRAME;
            return true;
        }
        else
        {
            return false;
        }
#endif
    }

protected:
    /**
     * @brief Processes a message fragment.
     * @param: fragment data
     * @param: fragment data length
     * @param: bytes from previous fragment
     * @param: operation code
     * @param: complete request flag
     * @return indicates if the frangment completed a message or not
     * @remarks
     */
    bool read_fragm(char *data, size_t length, unsigned aRemaining, int opCode, bool aFin)
    {
        if (opCode < 3)
        {
            if (!aRemaining && aFin && !_rx_fragment.length())
            {
                LOG_DEBUG("frag: %lu bytes -> msg", length);

#ifdef CHK_COMPRESSION_ON_MESSAGE
                if (_compressionStatus == WebSocket::CompressionStatus::COMPRESSED_FRAME)
                {
                    _compressionStatus = WebSocket::CompressionStatus::ENABLED;
                    data = session->inflate(data, length, session->maxPayload);
                    if (!data)
                    {
                        close("compression failed");
                        return true;
                    }
                }
#endif

#ifdef CHK_UTF8_MESSAGE
                if (opCode == 1 && !WebSocket::isValidUtf8((unsigned char *)data, length))
                {
                    close("invalid utf8 message");
                    return true;
                }
#endif

                ON_MESSAGE_HANDLER(data, length);

#if METRICS_LEVEL == 4
                //  Reset processing start time after each message
                startTimer();
#endif
            }
            else
            {
                LOG_DEBUG("frag: %lu bytes -> %lu added, %d remaining", _rx_fragment.length(), length, aRemaining);
                _rx_fragment.append(data, length);
                // _rx_fragment += std::string_view(data, length);

                if (!aRemaining && aFin)
                {
                    length = _rx_fragment.length();

#ifdef CHK_COMPRESSION_ON_MESSAGE
                    if (_compressionStatus == WebSocket::CompressionStatus::COMPRESSED_FRAME)
                    {
                        _compressionStatus = WebSocket::CompressionStatus::ENABLED;
                        _rx_fragment.append("...");
                        data = session->inflate(static_cast<char *>(_rx_fragment.data()), length, session->maxPayload);
                        if (!data)
                        {
                            close("compression failed");
                            return true;
                        }
                    }
                    else
                    {
                        data = static_cast<char *>(_rx_fragment.data());
                    }
#else
                    data = static_cast<char *>(_rx_fragment.data());
#endif

#ifdef CHK_UTF8_MESSAGE
                    if (opCode == 1 && !WebSocket::isValidUtf8((unsigned char *)data, length))
                    {
                        close("invalid utf8 message");
                        return true;
                    }
#endif

                    ON_MESSAGE_HANDLER(data, length);

#if METRICS_LEVEL == 4
                    //  Reset processing start time after each message
                    startTimer();
#endif

                    _rx_fragment.clear();
                    return false;
                }
            }
        }
        else if (!aRemaining && aFin && !_control_tip_len)
        {
            switch (opCode)
            {
            case CLOSE:
                LOG_DEBUG("->disconnect message received %d", opCode);
                CloseFrame frame;
                WebSocket::parseClosePayload(data, length, frame);
                close("disconnect message received", frame.code, frame.message, frame.length);
                return true;

            case PING:
                send(data, length, (OpCode)OpCode::PONG);
                onPing(data, length);
                break;

            case PONG:
                onPong(data, length);
                break;

            default:
                LOG_DEBUG("->unrecognized OpCode %d", opCode);
                break;
            }
        }
        else
        {
            LOG_DEBUG("frag: %lu bytes -> %lu added, %d remaining", _rx_fragment.length(), length, aRemaining);
            _rx_fragment.append(data, length);
            _control_tip_len += length;

            if (!aRemaining && aFin)
            {
                char *controlBuffer = static_cast<char *>(_rx_fragment.data()) + _rx_fragment.length() - _control_tip_len;

                switch (opCode)
                {
                case CLOSE:
                    CloseFrame frame;
                    WebSocket::parseClosePayload(controlBuffer, _control_tip_len, frame);
                    LOG_DEBUG("->disconnect message received %d", frame.code);
                    close("disconnect message received", frame.code, frame.message, frame.length);
                    return true;

                case PING:
                    send(controlBuffer, _control_tip_len, (OpCode)OpCode::PONG);
                    onPing(controlBuffer, _control_tip_len);
                    break;

                case PONG:
                    onPong(controlBuffer, _control_tip_len);
                    break;

                default:
                    LOG_DEBUG("->unrecognized OpCode %d", opCode);
                    break;
                }

                _rx_fragment.resize(_rx_fragment.length() - _control_tip_len);
                _control_tip_len = 0;
            }
        }

        return false;
    }

#pragma region HttpSocket

protected:
    /**
     * @brief Requests the upgrade to a WebSocket connection
     * @param socket instance of an open HttpSocket connection, must be allowed to send and receive HTTP formatted messages
     * @param path optional paramter, will be embedded into the HTTP request
     * @param hostname name of IP address of the remote server host
     * @param port port of the remote server host
     * @return WebSocket* on confirmation
     */
    bool upgrade(const std::string &path, const std::string &hostname, const std::string &port)
    {
        LOG_DEBUG("->upgrade-to-http, path: %s", path.c_str());

        //  Request upgrade
        std::ostringstream ssWebRequest;
        ssWebRequest << "GET /"
                     << path
                     << " HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nSec-WebSocket-Key: x3KJHMbDL1EzLkh9GBhXDw==\r\nHost: "
                     << hostname << ":" << port
                     << "\r\nSec-WebSocket-Version: 13\r\n\r\n";

        std::string sWebRequest = ssWebRequest.str();
        auto messagePtr = TxQueue::alloc(sWebRequest.length(), sWebRequest.data());

        if (!sendMessage(messagePtr))
        {
            //  Remarks: do not dispose of resources (e.g. queued messages) here because HttpSocket will be destroyed on the upgrade.
            //  Instead, call close() to terminate the connection and release resources
            LOG_DEBUG0("->upgrade request failed.");
            TxQueue::freeMessage(messagePtr);
            close("upgrade request failed");
            return false;
        }

        int nReadCount = 0;
        int nTimeouts = 0;
        int nSSLRead;

        do
        {
            //  Read upgrade response (wait until response is received)
            nSSLRead = SSL_read(_ssl_ptr, _rx_buffer, LARGE_BUFFER_SIZE - 1);

            if (nSSLRead > 0)
            {
                LOG_DEBUG("->http-response(%d)", nSSLRead);

                if (handleUpgrade(_rx_buffer, nSSLRead))
                {
                    LOG_DEBUG0("->upgrade confirmed.");

                    //  Notify the client
                    onConnect(hostname.c_str());

                    //  upgrade confirmed
                    return true;
                }

                //  stop after n messages
                nReadCount++;
                if (nReadCount >= 9)
                    return false;
            }
            else
            {
                //  handle read errors
                switch (SSL_get_error(_ssl_ptr, nSSLRead))
                {
                case SSL_ERROR_WANT_READ:

                    //  log timeout, but allow process to continue
                    nTimeouts++;

                    LOG_DEBUG0("->http-read: SSL_ERROR_WANT_READ");
                    LOG_DEBUG("->timeout after %d attempts", nTimeouts);

                    //  Notify client of failed read attempts as a timeout event!
                    onTimeout(nTimeouts);
                    if (nTimeouts < 0)
                    {
                        LOG_DEBUG0("->disconnect requested by client.");

                        //  Terminate connection on upgrade failures!
                        close("Upgrade request failed (disconnect requested by client).");
                        return false;
                    }
                    break;

                case SSL_ERROR_WANT_WRITE:

                    LOG_DEBUG0("->http-read: SSL_ERROR_WANT_WRITE.");

                    //  Terminate connection on upgrade failures!
                    close("Upgrade request failed (SSL_ERROR_WANT_WRITE).");
                    return false;

                case SSL_ERROR_SYSCALL:

                    LOG_DEBUG0("->http-read: SSL_ERROR_SYSCALL");

                    //  Terminate connection on upgrade failures!
                    close("Upgrade request failed (SSL_ERROR_SYSCALL).");
                    return false;

                default:

                    LOG_DEBUG0("->http-read: SSL_ERROR.");

                    //  Terminate connection on upgrade failures!
                    close("Upgrade request failed (SSL_ERROR).");
                    return false;
                }
            }

        } while (SSL_pending(_ssl_ptr));

        LOG_DEBUG0("->upgrade not confirmed.");

        //  Stop if receive buffer has been consumed
        return false;
    }

protected:
    /**
     * @brief Process upgrade response(s)
     * @param
     * @param
     * @return confirmation (true/false)
     * @remarks
     */
    bool handleUpgrade(char *data, size_t length)
    {
        if (_content_length)
        {
            if (_content_length >= length)
            {
                close("content length limit reached");
                return false;
            }
            else
            {
                data += _content_length;
                length -= _content_length;
                _content_length = 0;
            }
        }

        if (_rx_fragment.length())
        {
            if (_rx_fragment.length() + length > MAX_HEADER_BUFFER_SIZE)
            {
                close("http-buffer: size limit reached");
                return false;
            }

            LOG_DEBUG("upgd: %lu bytes -> %lu added", _rx_fragment.length(), length);
            //_rx_fragment.reserve(_rx_fragment.length() + length + CONSUME_POST_PADDING);
            _rx_fragment.append(data, length);
            data = static_cast<char *>(_rx_fragment.data());
            length = _rx_fragment.length();
        }

        /*
        * A websocket protocol has the following HTTP headers:
        *
        * Connection: Upgrade
        * Upgrade: Websocket
        *
        * The headers "Host", "Sec-WebSocket-Key", "Sec-WebSocket-Protocol" and "Sec-WebSocket-Version" are also required.
        * Don't check them here, since even an unsupported websocket protocol
        * request still IS a websocket request (in contrast to a standard HTTP
        * request). It will fail later in handle_websocket_request.
        */

        char *end = data + length;
        char *cursor = data;
        *end = '\r';
        HttpRequest::Header headers[MAX_HEADERS];

        do
        {
            char *lastCursor = cursor;
            if ((cursor = HttpRequest::getHeaders(cursor, end, headers, MAX_HEADERS)))
            {
                HttpRequest req(headers);
                if (req.getHeader("upgrade", 7))
                {
                    //  received upgrade request
                    LOG_DEBUG0("->http-headers: upgrade received.");

                    //  Process the confirmation message
                    consumeUpgrade(cursor, (size_t)(end - cursor));

                    //  Reset the buffers and return confirmation
                    _rx_fragment.clear();
                    return true;
                }
                else
                {
                    //  unexpected header
                    LOG_DEBUG0("->http-headers: other unexpected.");
                    close("upgrade confirmation expected");
                    return false;
                }
            }
            else if (!_rx_fragment.length())
            {
                if (length > MAX_HEADER_BUFFER_SIZE)
                {
                    LOG_DEBUG0("->http buffer: size limit reached.");
                    close("buffer size limit reached");
                    return false;
                }
                else
                {
                    //  continue receiving data
                    LOG_DEBUG0("->http-buffer: receive additional..");
                    LOG_DEBUG("upgd: %lu bytes -> %lu added", _rx_fragment.length(), end - lastCursor);
                    _rx_fragment.append(lastCursor, end - lastCursor);
                }
            }

        } while (cursor != end);

        //  create the internal buffer
        _rx_fragment.clear();
        LOG_DEBUG("upgd: %lu bytes -> erased", _rx_fragment.length());

        //  end of parsing, nothing to return if there was no upgrade
        return false;
    }

#pragma endregion HttpSocket

#pragma region WebSocket Protocol

protected:
    enum
    {
        SND_CONTINUATION = 1,
        SND_NO_FIN = 2,
        SND_COMPRESSED = 64
    };

    static inline bool isFin(const char *frame) { return *((unsigned char *)frame) & 128; }
    static inline bool rsv1(const char *frame) { return *((unsigned char *)frame) & 64; }
    static inline bool rsv23(const char *frame) { return *((unsigned char *)frame) & 48; }
    static inline void getOpCode(const char *frame, unsigned char &outOpCode) { outOpCode = *((unsigned char *)frame) & 15; }
    static inline void payloadLength(const char *frame, unsigned char &outLength) { outLength = ((unsigned char *)frame)[1] & 127; }

    static inline void unmaskImprecise(char *dst, const char *src, char *mask, const size_t length)
    {
        for (size_t n = (length >> 2) + 1; n; --n)
        {
            *(dst++) = *(src++) ^ mask[0];
            *(dst++) = *(src++) ^ mask[1];
            *(dst++) = *(src++) ^ mask[2];
            *(dst++) = *(src++) ^ mask[3];
        }
    }

    static inline void unmaskImpreciseCopyMask(char *dst, const char *src, const char *maskPtr, const size_t length)
    {
        char mask[4] = {maskPtr[0], maskPtr[1], maskPtr[2], maskPtr[3]};
        unmaskImprecise(dst, src, mask, length);
    }

    static inline void rotateMask(const size_t offset, char *mask)
    {
        char originalMask[4] = {mask[0], mask[1], mask[2], mask[3]};
        mask[(0 + offset) % 4] = originalMask[0];
        mask[(1 + offset) % 4] = originalMask[1];
        mask[(2 + offset) % 4] = originalMask[2];
        mask[(3 + offset) % 4] = originalMask[3];
    }

    static inline void unmaskInplace(char *data, const char *stop, const char *mask)
    {
        while (data < stop)
        {
            *(data++) ^= mask[0];
            *(data++) ^= mask[1];
            *(data++) ^= mask[2];
            *(data++) ^= mask[3];
        }
    }

    /**
     * @brief
     * @param
     * @param
     * @param
     * @return
     * @remarks
     */
    static inline void parseClosePayload(char *src, const size_t length, CloseFrame &outFrame)
    {
        outFrame = {};
        if (length >= 2)
        {
            memcpy(&outFrame.code, src, 2);
            outFrame = {ntohs(outFrame.code), src + 2, length - 2};

            if ((outFrame.code < 1000) || (outFrame.code > 4999) || (outFrame.code > 1011 && outFrame.code < 4000) || (outFrame.code >= 1004 && outFrame.code <= 1006))
            {
                outFrame = {};
            }

#ifdef CHK_UTF8_MESSAGE
            else if (!isValidUtf8((unsigned char *)outFrame.message, outFrame.length))
            {
                outFrame = {};
            }
#endif
        }
    }

    /**
     * @brief
     * @param
     * @param
     * @param
     * @param
     * @return
     * @remarks
     */
    static inline size_t formatClosePayload(char *dst, uint16_t code, const char *message, const size_t length)
    {
        if (code)
        {
            code = htons(code);
            memcpy(dst, &code, 2);
            memcpy(dst + 2, message, length);
            return length + 2;
        }
        return 0;
    }

    /**
     * @brief
     * @param
     * @param
     * @param
     * @param
     * @return
     * @remarks
     */
    static inline size_t formatMessage(char *dst, const char *src, size_t length, OpCode opCode, size_t reportedLength, bool compressed)
    {
        size_t messageLength;
        size_t headerLength;
        if (reportedLength < 126)
        {
            headerLength = 2;
            dst[1] = reportedLength;
        }
        else if (reportedLength <= UINT16_MAX)
        {
            headerLength = 4;
            dst[1] = 126;
            *((uint16_t *)&dst[2]) = htons(reportedLength);
        }
        else
        {
            headerLength = 10;
            dst[1] = 127;
            *((uint64_t *)&dst[2]) = htobe64(reportedLength);
        }

        int flags = 0;
        dst[0] = ((flags & SND_NO_FIN) ? 0 : 128) | (compressed ? SND_COMPRESSED : 0);
        if (!(flags & SND_CONTINUATION))
        {
            dst[0] |= opCode;
        }

        char mask[4];
        {
            dst[1] |= 0x80;
            uint32_t random = rand();
            memcpy(mask, &random, 4);
            memcpy(dst + headerLength, &random, 4);
            headerLength += 4;
        }

        messageLength = headerLength + length;
        memcpy(dst + headerLength, src, length);

        {
            //TODO: must fix - it overwrites up to 3 bytes outside of the given buffer!
            //WebSocket::unmaskInplace(dst + headerLength, dst + headerLength + length, mask);

            // this is not optimal
            char *start = dst + headerLength;
            char *stop = start + length;
            int i = 0;
            while (start != stop)
            {
                (*start++) ^= mask[i++ % 4];
            }
        }

        return messageLength;
    }

    /**
     * @brief Processor for received data
     * @param src
     * @param length
     * @remarks called by the upgrade() function. for performance reasons the other calls have been replaced everywhere else with the actual body of the function.
     */
    void consumeUpgrade(char *src, size_t length)
    {
        // LOG_DEBUG("consume -> %d bytes", length);
        // LOG_DEBUG("\nc0  -> %8d %8lu", length, strlen(src));

        if (_wsState.spillLength)
        {
            // LOG_DEBUG("spill (%du)", _wsState.spillLength);
            src -= _wsState.spillLength;
            length += _wsState.spillLength;
            memcpy(src, _wsState.spill, _wsState.spillLength);
            // LOG_DEBUG("spill  : %d", payloadLength(src));
        }

        if (_wsState.wantsHead)
        {

        consumeNext:
            while (length >= SHORT_MESSAGE_HEADER)
            {
                payloadLength(src, _consume_payload_len);

                // invalid reserved bits / invalid opcodes / invalid control frames / set compressed frame
                getOpCode(src, _cOpCode);
                if ((rsv1(src) && !setCompressed()) || rsv23(src) || (_cOpCode > 2 && _cOpCode < 8) || _cOpCode > 10 || (_cOpCode > 2 && (!isFin(src) || _consume_payload_len > 125)))
                {
                    close("invalid message properties (e.g. reserved bits, opcode, control frame, compression)", 0);
                    return;
                }

                if (_consume_payload_len < 126)
                {
                    // LOG_DEBUG("c1  : %d", _consume_payload_len);
                    if (read<SHORT_MESSAGE_HEADER, uint8_t>(_consume_payload_len, src, length))
                    {
                        return;
                    }
                }
                else if (_consume_payload_len == 126)
                {
                    // LOG_DEBUG("c2  : %d", _consume_payload_len);
                    if (length < MEDIUM_MESSAGE_HEADER)
                    {
                        break;
                    }
                    else if (read<MEDIUM_MESSAGE_HEADER, uint16_t>(ntohs(*(uint16_t *)&src[2]), src, length))
                    {
                        return;
                    }
                }
                else if (length < LONG_MESSAGE_HEADER)
                {
                    // LOG_DEBUG("c3  : %d", _consume_payload_len);
                    break;
                }
                else if (read<LONG_MESSAGE_HEADER, uint64_t>(be64toh(*(uint64_t *)&src[2]), src, length))
                {
                    // LOG_DEBUG("c4  : %d", _consume_payload_len);
                    return;
                }
            }

            if (length)
            {
                //  spilled data
                memcpy(_wsState.spill, src, length);
                _wsState.spillLength = length;
                // LOG_DEBUG("c5  : %d", payloadLength(src));
            }
        }
        else if (_remaining_bytes <= length)
        {
            // LOG_DEBUG("src %8lu -> %4d bytes - %d", strlen(src), length, _remaining_bytes);
            // LOG_DEBUG("\nf3(%d-%d):", length, _remaining_bytes);
            if (read_fragm(src, _remaining_bytes, 0, _wsState.opCode[_wsState.opStack], _wsState.lastFin))
            {
                return; //consumed, do not allow further message processing?!
            }

            if (_wsState.lastFin)
            {
                _wsState.opStack--;
            }

            src += _remaining_bytes;
            length -= _remaining_bytes;
            _wsState.wantsHead = true;
            goto consumeNext; //continue
        }
        else
        {
            // LOG_DEBUG("\nf4(%d-%d):", length, _remaining_bytes);
            _remaining_bytes -= length;
            read_fragm(src, length, _remaining_bytes, _wsState.opCode[_wsState.opStack], _wsState.lastFin);
            return; //consumed, do not allow further message processing?!
        }
    }

    template <unsigned MESSAGE_HEADER, typename T>
    inline bool read(const T aPayloadLength, char *&src, size_t &length)
    {
        getOpCode(src, _cOpCode);
        if (_cOpCode)
        {
            if (_wsState.opStack == 1 || (!_wsState.lastFin && _cOpCode < 2))
            {
                close("invalid opCode");
                return true;
            }
            _wsState.opCode[++_wsState.opStack] = (OpCode)_cOpCode;
        }
        else if (_wsState.opStack == -1)
        {
            close("invalid opStack");
            return true;
        }

        _wsState.lastFin = isFin(src);

#ifdef USE_COMPRESSION
        if (refusePayloadLength(aPayloadLength))
        {
            close("invalid payload length");
            return true;
        }
#endif

        if (aPayloadLength + MESSAGE_HEADER <= length)
        {
            // LOG_DEBUG("\nf1(%d-%d):", length, _remaining_bytes);
            if (read_fragm(src + MESSAGE_HEADER, aPayloadLength, 0, _wsState.opCode[_wsState.opStack], _wsState.lastFin))
            {
                return true;
            }

            if (isFin(src))
            {
                _wsState.opStack--;
            }

            src += aPayloadLength + MESSAGE_HEADER;
            length -= aPayloadLength + MESSAGE_HEADER;
            _wsState.spillLength = 0;
            return false;
        }
        else
        {
            _wsState.spillLength = 0;
            _wsState.wantsHead = false;
            _remaining_bytes = (size_t)(aPayloadLength - length + MESSAGE_HEADER);
            _consume_msg_fin = isFin(src);
            src += MESSAGE_HEADER;
            // LOG_DEBUG("\nf2(%d-%d):", length, _remaining_bytes);
            read_fragm(src, length - MESSAGE_HEADER, _remaining_bytes, _wsState.opCode[_wsState.opStack], _consume_msg_fin);
            return true;
        }
    }

#pragma endregion

#pragma region Transmission Blocks

    unsigned getBlockSize(const unsigned length) const
    {
        return (unsigned)((length >> 4) + bool(length & 15));
    }

    char *getBlockSmall(const unsigned index) const
    {
        if (_tx_buffer[index])
        {
            char *memory = _tx_buffer[index];
            _tx_buffer[index] = nullptr;
            return memory;
        }
        else
        {
            return new char[index << 4];
        }
    }

    void freeBlockSmall(char *memory, const unsigned index) const
    {
        if (!_tx_buffer[index])
        {
            _tx_buffer[index] = memory;
        }
        else
        {
            delete[] memory;
        }
    }

#pragma endregion

#ifdef USE_COMPRESSION

    inline bool refusePayloadLength(uint64_t length)
    {
        return (length > zxBufferSize);
    }

    inline bool slidingDeflateWindow()
    {
        return (_ext_options & Options::SLIDING_DEFLATE_WINDOW);
    }

    static z_stream *allocateDefaultCompressor(z_stream *zStream)
    {
        deflateInit2(zStream, 1, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
        return zStream;
    }

    char *deflate(char *data, size_t &length, z_stream *slidingDeflateWindow)
    {
        zxBufferStr.clear();

        z_stream *compressor = slidingDeflateWindow ? slidingDeflateWindow : &deflationStream;

        compressor->next_in = (Bytef *)data;
        compressor->avail_in = (unsigned)length;

        // note: zlib requires more than 6 bytes with Z_SYNC_FLUSH
        const int DEFLATE_OUTPUT_CHUNK = LARGE_BUFFER_SIZE;

        do
        {
            compressor->next_out = (Bytef *)zxBuffer;
            compressor->avail_out = DEFLATE_OUTPUT_CHUNK;

            int err = ::deflate(compressor, Z_SYNC_FLUSH);
            if (Z_OK == err && compressor->avail_out == 0)
            {
                zxBufferStr.append(zxBuffer, DEFLATE_OUTPUT_CHUNK - compressor->avail_out);
                continue;
            }
            else
            {
                break;
            }
        } while (true);

        // note: should not change avail_out
        if (!slidingDeflateWindow)
        {
            deflateReset(compressor);
        }

        if (zxBufferStr.length())
        {
            zxBufferStr.append(zxBuffer, DEFLATE_OUTPUT_CHUNK - compressor->avail_out);

            length = zxBufferStr.length() - 4;
            return (char *)zxBufferStr.data();
        }

        length = DEFLATE_OUTPUT_CHUNK - compressor->avail_out - 4;
        return zxBuffer;
    }

    char *inflate(char *data, size_t &length, size_t zxBufferSize)
    {
        // todo: let's go through this code once more some time!
        zxBufferStr.clear();

        inflationStream.next_in = (Bytef *)data;
        inflationStream.avail_in = (unsigned)length;

        int err;
        do
        {
            inflationStream.next_out = (Bytef *)zxBuffer;
            inflationStream.avail_out = LARGE_BUFFER_SIZE;
            err = ::inflate(&inflationStream, Z_FINISH);
            if (!inflationStream.avail_in)
            {
                break;
            }

            zxBufferStr.append(zxBuffer, LARGE_BUFFER_SIZE - inflationStream.avail_out);
        } while (err == Z_BUF_ERROR && zxBufferStr.length() <= zxBufferSize);

        inflateReset(&inflationStream);

        if ((err != Z_BUF_ERROR && err != Z_OK) || zxBufferStr.length() > zxBufferSize)
        {
            length = 0;
            return nullptr;
        }

        if (zxBufferStr.length())
        {
            zxBufferStr.append(zxBuffer, LARGE_BUFFER_SIZE - inflationStream.avail_out);

            length = zxBufferStr.length();
            return (char *)zxBufferStr.data();
        }

        length = LARGE_BUFFER_SIZE - inflationStream.avail_out;
        return zxBuffer;
    }
#endif

protected:
    virtual void onConnect(const char *aURI)
    {
        LOG_EVENT("Connected to %s", aURI);
    }

    virtual void onDisconnect(const char *message, size_t length, const int code)
    {
        LOG_EVENT("Disconnected. %s", message);
    }

    virtual void onTimeout(int &code)
    {
        LOG_EVENT("Timeout (%d).", code);
    }

    virtual void onError(const char *message, size_t length, const ErrorCode code)
    {
        LOG_EVENT("Error (%d): %s", (int)code, (char *)message);
    }

    virtual void onPing(const char *message, size_t length)
    {
        LOG_EVENT("Ping => %s", std::string(message, length).c_str());
    }

    virtual void onPong(const char *message, size_t length)
    {
        LOG_EVENT("Pong => %s", std::string(message, length).c_str());
    }

    /**
     * @brief
     * @remarks the calls to this virtual function can be replaced with a static function call by including the "globals_handlers.h" header or your custom implementation with the same signature and header macros. Search for onMessage_static in this implementation...
     */
    virtual void onMessage(const char *message, size_t length)
    {
        LOG_EVENT("MSG => %s", std::string(message, length).c_str());
    }
};

} // namespace sWS

#endif // SOCKET_WEB_H