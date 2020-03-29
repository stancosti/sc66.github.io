#ifndef __EXTERN_H__
#define __EXTERN_H__

#include <string>
#include <cstring>
#include <thread>
#include <mutex>
#include <chrono>
#include <sstream>

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

// #include <netinet/in.h>
// #include <fcntl.h>
// #include <endian.h>

#ifdef USE_COMPRESSION
#include <zlib.h>
#endif

#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define SSL_CTX_up_ref(x) x->references++
#define SSL_up_ref(x) x->references++
#endif

#endif