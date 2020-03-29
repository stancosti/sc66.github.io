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
#ifndef __WEB_SESSION_H__
#define __WEB_SESSION_H__

#include "extern.h"
#include <vector>

namespace sWS
{

struct WebSession
{
private:
    SSL_CTX *_ssl_context_global;
    std::vector<SSL *> _ssl_array;

public:
    WebSession() : _ssl_array()
    {
        //  OpenSSL initialization
        SSL_library_init();

        //  Setup the global SSL context
        _ssl_context_global = SSL_CTX_new(SSLv23_client_method());
        SSL_CTX_set_options(_ssl_context_global, SSL_OP_NO_SSLv3);
        // SSL_CTX_set_options(_ssl_context_global, SSL_MODE_RELEASE_BUFFERS);
    }

    virtual ~WebSession()
    {
        //  Release SSL resources
        for (auto it = _ssl_array.begin(), end = _ssl_array.end(); it != end; ++it)
        {
            // release(it);
        }
        SSL_CTX_free(_ssl_context_global);
    }

    /**
     * @remarks Disable unwanted copying construction:
     */
    // WebSession(const WebSession &) = delete;

    /**
     * @remarks Disable unwanted copying assignment:
     */
    WebSession &operator=(const WebSession &copy) = delete;

    /**
     * @brief Create a new SSL structure which is needed to hold the data for a TLS/SSL connection. The new structure inherits the settings of the underlying context.
     * @return
     */
    SSL *new_ssl_context() const
    {
        SSL *ssl_handle = SSL_new(_ssl_context_global);

        // SSL_set_mode(ssl_handle, SSL_MODE_RELEASE_BUFFERS); //resetting buffers affects performance. commenting it out gives a boost of about 30 microseconds per message!!!

        //  Save reference to ensure cleanup on destruction
        // _ssl_array.insert(_ssl_array.begin(), ssl_handle);

        return ssl_handle;
    }

    /**
     * @brief
     * @param aSSL
     * @remarks
     */
    void release(SSL *aSSL) const
    {
        // _ssl_array(_ssl_array.begin(), ssl_handle);

        //  release ssl resources when closing, not in the destructor!!
        //  we cannot release ssl resources on upgrade from http to web sockets. the ssl is reused in that case!!
        SSL_shutdown(aSSL);
        SSL_free(aSSL);
    }

    /**
     * @brief
     * @param uri
     * @param secure
     * @param hostname
     * @param port
     * @param path
     * @remarks
     */
    static bool parse_uri(const std::string &uri, bool &secure, std::string &hostname, std::string &port, std::string &path)
    {
        port = std::string("80");
        secure = false;
        size_t offset = 5;
        if (!uri.compare(0, 6, "wss://"))
        {
            port = std::string("443");
            secure = true;
            offset = 6;
        }
        else if (uri.compare(0, 5, "ws://"))
        {
            return false;
        }

        if (offset == uri.length())
        {
            return false;
        }

        if (uri[offset] == '[')
        {
            if (++offset == uri.length())
            {
                return false;
            }
            size_t endBracket = uri.find(']', offset);
            if (endBracket == std::string::npos)
            {
                return false;
            }
            hostname = uri.substr(offset, endBracket - offset);
            offset = endBracket + 1;
        }
        else
        {
            hostname = uri.substr(offset, uri.find_first_of(":/", offset) - offset);
            offset += hostname.length();
        }

        if (offset == uri.length())
        {
            path.clear();
            return true;
        }

        if (uri[offset] == ':')
        {
            offset++;
            std::string portStr = uri.substr(offset, uri.find('/', offset) - offset);
            if (portStr.length())
            {
                try
                {
                    port = stoi(portStr);
                }
                catch (...)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
            offset += portStr.length();
        }

        if (offset == uri.length())
        {
            path.clear();
            return true;
        }

        if (uri[offset] == '/')
        {
            path = uri.substr(++offset);
        }

        return true;
    }
};

} // namespace sWS

#endif // __WEB_SESSION_H__