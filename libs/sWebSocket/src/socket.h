/**
 * @brief
 * @remarks using original source code from the uWebSockets library
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
#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "extern.h"
#include "logger.h"

namespace sWS
{

#define INVALID_SOCKET -1

/**
 * @brief Raw socket implementation
 */
struct Socket
{
private:
    typedef int os_fd_socket_t;

    struct
    {
        os_fd_socket_t fd : 28;
        int shuttingDown : 4;
    } sState = {INVALID_SOCKET, false};

public:
    Socket() {}
    virtual ~Socket() {}

    void connect(const char *hostname, const char *port, const SSL *aSSL = nullptr, uint timeout = 5000)
    {
        LOG_DEBUG("->connecting: %s, %s. timeout: %u", hostname, port, timeout);

        addrinfo hints;
        memset(&hints, 0, sizeof(addrinfo));
        hints.ai_family = AF_INET; //AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo *addr = nullptr;
        if (::getaddrinfo(hostname, port, &hints, &addr) != 0)
        {
            LOG_DEBUG0("->invalid addrinfo");
            throw new std::runtime_error("Cannot retrieve network address information.");
        }

        LOG_DEBUG0("->socket_instance");

        //  create new socket connection
        int flags = 0;
        os_fd_socket_t fd = socket(addr->ai_family, addr->ai_socktype | flags, addr->ai_protocol);

        if (fd == INVALID_SOCKET)
        {
            ::freeaddrinfo(addr);
            LOG_DEBUG0("->invalid socket");
            throw new std::runtime_error("Failed to initialize new socket connection.");
        }

        if (aSSL)
        {
            //  OpenSSL treats raw sockets as int file descriptors
            LOG_DEBUG("->ssl (%d)", fd);
            SSL_set_fd((SSL *)aSSL, (int)fd);
        }

        int rc;

        /**
             * TCP sockets under Linux come with a rich set of options with which you can manipulate the functioning of the OS TCP/IP stack.
             * A few options are important for performance, such as the TCP send and receive buffer sizes:
             *
             * I am using conservative values here. Obviously, they should be much higher for Gigabit networks.
             * These values are determined by the bandwidth delay product. Interestingly, I have never found this to be an issue, so I doubt if this would give you a performance boost.
             * It still is worth mentioning, because the TCP window size alone can give you optimal throughput.
             *
             * It is also a good idea to enable PMTU (Path Maximum Transmission Unit) discovery to avoid IP fragmentation.
             * IP fragmentation can affect not just performance, but surely it's more important regarding performance than anything else.
             * To avoid fragmentation at any cost, several HTTP servers use conservative packet sizes.
             * Doing so is not a very good thing, as there is a corresponding increase in protocol overhead.
             * More packets mean more headers and wasted bandwidth.
             */

        int sndsize = 16384;
        LOG_DEBUG("->snd_buffer(%d)", sndsize);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&sndsize, (int)sizeof(sndsize));

        int rcvsize = 32768;
        LOG_DEBUG("->rcv_buffer(%d)", rcvsize);
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvsize, (int)sizeof(rcvsize));

        //SO_RCVLOWAT

        //  read timeout interval
        struct timeval interval = {timeout / 1000, (timeout % 1000) * 1000};
        LOG_DEBUG("->rcv_timeout(%u)", timeout);
        rc = ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&interval, sizeof(struct timeval));

        if (rc < 0)
        {
            LOG_DEBUG0("->setsockopt(SO_RCVTIMEO) failed");
            throw new std::runtime_error("Cannot set connection properties (SO_RCVTIMEO).");
        }

        //  send timeout interval
        LOG_DEBUG("->snd_timeout(%u)", timeout);
        rc = ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&interval, sizeof(struct timeval));

        if (rc < 0)
        {
            LOG_DEBUG0("->setsockopt(SO_SNDTIMEO) failed");
            throw new std::runtime_error("Cannot set connection properties (SO_SNDTIMEO).");
        }

#ifdef USE_METRICS

        // LOG_DEBUG0("->set_metrics");

        // sockaddr_in  addr_in;
        // addr_in.sin_addr.s_addr    = inet_addr(addr->ai_addr->sa_data);
        // addr_in.sin_port           = htons(atoi(port));
        // addr_in.sin_family         = AF_INET;

        // //  provide socket level _metrics (e.g. collect and report OS-level timestamps)
        // _metrics->write(fd, addr_in);
#endif

        LOG_DEBUG("->connect (socket_id: %d)", fd);

        //  open connection
        rc = ::connect(fd, addr->ai_addr, addr->ai_addrlen);

        //  cleanup address
        ::freeaddrinfo(addr);

        if (rc < 0)
        {
            throw new std::runtime_error("Cannot connect to requested address.");
        }

        //  save socket's file descriptor
        sState.fd = fd;
        sState.shuttingDown = false;
        LOG_DEBUG("->connected (socket_id: %d)", fd);
    }

    /*
    bool connect(char *host, int port, int timeout)
    {
        TIMEVAL Timeout;
        Timeout.tv_sec = timeout;
        Timeout.tv_usec = 0;
        struct sockaddr_in address; //the libc network address data structure

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        address.sin_addr.s_addr = inet_addr(host); // assign the address
        address.sin_port = htons(port);            // translate int2port num
        address.sin_family = AF_INET;

        //set the socket in non-blocking
        unsigned long iMode = 1;
        int iResult = ioctlsocket(sock, FIONBIO, &iMode);
        if (iResult != NO_ERROR)
        {
            LOG_DEBUG("->ioctlsocket failed with error: %ld", iResult);
        }

        if (connect(sock, (struct sockaddr *)&address, sizeof(address)) == false)
        {
            return false;
        }

        // restart the socket mode
        iMode = 0;
        iResult = ioctlsocket(sock, FIONBIO, &iMode);
        if (iResult != NO_ERROR)
        {
            LOG_DEBUG("->ioctlsocket failed with error: %ld", iResult);
        }

        fd_set Write, Err;
        FD_ZERO(&Write);
        FD_ZERO(&Err);
        FD_SET(sock, &Write);
        FD_SET(sock, &Err);

        // check if the socket is ready
        select(0, NULL, &Write, &Err, &Timeout);
        if (FD_ISSET(sock, &Write))
        {
            return true;
        }

        return false;
    }*/

    void close(const char *reason)
    {
        //  close connection entirely
        LOG_DEBUG("->socket closing (%d)", sState.fd);
        ::close(sState.fd);

        //  mark socket as unusable
        sState.fd = INVALID_SOCKET;
    }

    void shutdown(bool linkDown, bool linkUp)
    {
        sState.shuttingDown = true;

        if (sState.fd != INVALID_SOCKET)
        {
            if (linkDown)
            {
                //  block the down link
                ::shutdown(sState.fd, SHUT_RD);
                LOG_DEBUG0("->shutdown downlink");
            }

            if (linkUp)
            {
                //  block the upload link
                ::shutdown(sState.fd, SHUT_WR);
                LOG_DEBUG0("->shutdown uplink");
            }
        }
    }

    inline bool isClosed() const
    {
        return sState.fd == INVALID_SOCKET;
    }

    inline bool isShuttingDown() const
    {
        return sState.shuttingDown;
    }

    void setNoDelay(int enable) const
    {
        ::setsockopt(sState.fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));
    }

    void setTimeout(uint readMs, uint writeMs) const
    {
        LOG_DEBUG("->set_timeouts (%u, %u)", readMs, writeMs);

        //  set read timeout interval
        struct timeval interval1 = {readMs / 1000, (readMs % 1000) * 1000};
        int rc = ::setsockopt(sState.fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&interval1, sizeof(struct timeval));

        if (rc < 0)
        {
            LOG_DEBUG0("->setsockopt(SO_RCVTIMEO) failed");
            throw new std::runtime_error("Cannot set connection properties (SO_RCVTIMEO).");
        }

        //  set write timeout interval
        struct timeval interval2 = {writeMs / 1000, (writeMs % 1000) * 1000};
        ::setsockopt(sState.fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&interval2, sizeof(struct timeval));

        if (rc < 0)
        {
            LOG_DEBUG0("->setsockopt(SO_SNDTIMEO) failed");
            throw new std::runtime_error("Cannot set connection properties (SO_SNDTIMEO).");
        }
    }

    inline void cork(int enable) const
    {
        // Remarks: disabled when the SO_NODELAY option is used
        ::setsockopt(sState.fd, IPPROTO_TCP, TCP_CORK, &enable, sizeof(int));
    }

    /**
     * @brief
     * @param
     * @param
     * @param
     * @remarks
     */
    bool send(const char *aMessage, const size_t aLength, int &aSent, SSL *aSSL)
    {
        aSent = SSL_write(aSSL, aMessage, (int)aLength);

        if (aSent == (int)aLength)
        {
            return true;
        }
        else if (aSent < 0)
        {
            switch (SSL_get_error(aSSL, (int)aSent))
            {
            case SSL_ERROR_WANT_READ:
                throw new std::runtime_error("Failed to send message (SSL_ERROR_WANT_READ).");

            case SSL_ERROR_WANT_WRITE:
                throw new std::runtime_error("Failed to send message (SSL_ERROR_WANT_WRITE).");

            default:
                throw new std::runtime_error("Failed to send message (SSL_ERROR).");
            }
        }
        else
        {
            throw new std::runtime_error("Failed to send the entire message.");
        }
    }

#ifdef USE_METRICS
    struct Metrics
    {
        struct msghdr msg;
        struct cmsghdr *cmsg;
        struct iovec iov;
        char pktbuf[2048];
        char ctrl[CMSG_SPACE(sizeof(struct timeval))];

        inline void write(const int fd, sockaddr_in addr_in)
        {
            //  request message timestamps
            int timestampOn = 1;
            int rc = ::setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, (int *)&timestampOn, sizeof(timestampOn));

            if (rc < 0)
            {
                std::__throw_runtime_error("Cannot set socket timestamp mode (SO_TIMESTAMP).");
            }

            // struct iovec iov;
            // char pktbuf[2048];
            // char ctrl[CMSG_SPACE(sizeof(struct timeval))];

            memset(pktbuf, 0, strlen(pktbuf));

            cmsg = (cmsghdr *)&ctrl;

            msg.msg_control = (char *)ctrl;
            msg.msg_controllen = sizeof(ctrl);
            msg.msg_name = &addr_in;
            msg.msg_namelen = sizeof(addr_in);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            iov.iov_base = pktbuf;
            iov.iov_len = sizeof(pktbuf);
        }

        inline void read(const int fd)
        {
            int rc = ::recvmsg(fd, &msg, 0);

            if (rc < 0)
            {
                printf("cannot read message headers\n");
                return;
            }

            struct timeval time_kernel, time_user;

            gettimeofday(&time_user, NULL);

            if (cmsg->cmsg_level == SOL_SOCKET &&
                cmsg->cmsg_type == SCM_TIMESTAMP &&
                cmsg->cmsg_len == CMSG_LEN(sizeof(time_kernel)))
            {
                memcpy(&time_kernel, CMSG_DATA(cmsg), sizeof(time_kernel));
            }

            printf("time_kernel                  : %ld.%ld\n", time_kernel.tv_sec, time_kernel.tv_usec);

            // printf("\n");
            // printf("time_kernel                  : %d.%06d\n", (int)time_kernel.tv_sec, (int)time_kernel.tv_usec);
            // printf("time_user                    : %d.%06d\n", (int)time_user.tv_sec, (int)time_user.tv_usec);
            // printf("time_diff                    : %d.%06d\n", (int)(time_user.tv_sec - time_kernel.tv_sec), (int)(time_user.tv_usec - time_kernel.tv_usec));

            // static int totalUsec;
            // static int totalPackets;
            // static int latencies[NUM_LATENCIES];
            // static int rollingAverage;
            // static int index;

            // int timediff;
            // timediff = (time_user.tv_sec - time_kernel.tv_sec) * 1000000 + (time_user.tv_usec - time_kernel.tv_usec);
            // totalUsec += timediff;
            // ++totalPackets;

            // rollingAverage += timediff;
            // rollingAverage -= latencies[index];
            // latencies[index] = timediff;
            // index = (index + 1) % NUM_LATENCIES;

            // printf("Total Average                : %d/%d = %.2f us\n", totalUsec,
            //        totalPackets,
            //        (float)totalUsec / totalPackets);
            // printf("Rolling Average (%d samples) : %.2f us\n", NUM_LATENCIES,
            //        (float)rollingAverage / NUM_LATENCIES);
        }

        /**
         * @brief
         * @return char* printable system time
         */
        static inline char *timenow()
        {
            time_t rawtime;
            time(&rawtime);

            struct tm *timeinfo;
            timeinfo = localtime(&rawtime);

            static char buffer[64];
            strftime(buffer, 64, "%Y-%m-%d %H:%M:%S", timeinfo);
            return buffer;
        }
    };
#endif
};

} // namespace sWS

#endif