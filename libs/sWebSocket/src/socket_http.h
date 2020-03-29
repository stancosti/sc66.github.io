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
#ifndef __SOCKET_HTTP_H__
#define __SOCKET_HTTP_H__

#define MAX_HEADERS 100
#define MAX_HEADER_BUFFER_SIZE 2048

namespace sWS
{

enum HttpMethod
{
    METHOD_GET,
    METHOD_POST,
    METHOD_PUT,
    METHOD_DELETE,
    METHOD_PATCH,
    METHOD_OPTIONS,
    METHOD_HEAD,
    METHOD_TRACE,
    METHOD_CONNECT,
    METHOD_INVALID
};

struct HttpRequest
{
    struct Header
    {
        char *key, *value;
        unsigned int keyLength, valueLength;
        operator bool()
        {
            return key;
        }
    };

    const Header *headers;

    HttpRequest(Header *headers = nullptr) : headers(headers) {}

    ~HttpRequest() {}

    Header getHeader(const char *key)
    {
        return getHeader(key, strlen(key));
    }

    Header getHeader(const char *key, size_t length)
    {
        if (headers)
        {
            for (Header *h = (Header *)headers; *++h;)
            {
                if (h->keyLength == length && !strncmp(h->key, key, length))
                {
                    return *h;
                }
            }
        }
        return {nullptr, nullptr, 0, 0};
    }

    Header getUrl()
    {
        if (headers->key)
        {
            return *headers;
        }
        return {nullptr, nullptr, 0, 0};
    }

    HttpMethod getMethod()
    {
        if (!headers->key)
        {
            return METHOD_INVALID;
        }
        switch (headers->keyLength)
        {
        case 3:
            if (!strncmp(headers->key, "get", 3))
            {
                return METHOD_GET;
            }
            else if (!strncmp(headers->key, "put", 3))
            {
                return METHOD_PUT;
            }
            break;
        case 4:
            if (!strncmp(headers->key, "post", 4))
            {
                return METHOD_POST;
            }
            else if (!strncmp(headers->key, "head", 4))
            {
                return METHOD_HEAD;
            }
            break;
        case 5:
            if (!strncmp(headers->key, "patch", 5))
            {
                return METHOD_PATCH;
            }
            else if (!strncmp(headers->key, "trace", 5))
            {
                return METHOD_TRACE;
            }
            break;
        case 6:
            if (!strncmp(headers->key, "delete", 6))
            {
                return METHOD_DELETE;
            }
            break;
        case 7:
            if (!strncmp(headers->key, "options", 7))
            {
                return METHOD_OPTIONS;
            }
            else if (!strncmp(headers->key, "connect", 7))
            {
                return METHOD_CONNECT;
            }
            break;
        }
        return METHOD_INVALID;
    }

    // UNSAFETY NOTE: assumes *end == '\r' (might unref end pointer)
    static char *getHeaders(char *buffer, char *end, Header *headers, size_t maxHeaders)
    {
        for (unsigned int i = 0; i < maxHeaders; ++i)
        {
            for (headers->key = buffer; (*buffer != ':') & (*buffer > 32); *(buffer++) |= 32)
                ;

            if (*buffer == '\r')
            {
                if ((buffer != end) & (buffer[1] == '\n') & (i > 0))
                {
                    headers->key = nullptr;
                    return buffer + 2;
                }
                else
                {
                    return nullptr;
                }
            }
            else
            {
                headers->keyLength = (unsigned int)(buffer - headers->key);
                for (buffer++; (*buffer == ':' || *buffer < 33) && *buffer != '\r'; buffer++)
                    ;
                headers->value = buffer;
                buffer = (char *)memchr(buffer, '\r', end - buffer); //for (; *buffer != '\r'; buffer++);
                if (buffer /*!= end*/ && buffer[1] == '\n')
                {
                    headers->valueLength = (unsigned int)(buffer - headers->value);
                    buffer += 2;
                    headers++;
                }
                else
                {
                    return nullptr;
                }
            }
        }
        return nullptr;
    }
};

} // namespace sWS

#endif // SOCKET_HTTP_H