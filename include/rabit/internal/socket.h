/*!
 *  Copyright (c) 2014-2019 by Contributors
 * \file socket.h
 * \brief this file aims to provide a wrapper of sockets
 * \author Tianqi Chen
 */
#ifndef RABIT_INTERNAL_SOCKET_H_
#define RABIT_INTERNAL_SOCKET_H_
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif  // _MSC_VER
#else
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#endif  // defined(_WIN32)
#include <string>
#include <cstring>
#include <vector>
#include <unordered_map>
#include "utils.h"
#include <iostream>

// mbedtls settings
#if !defined(MBEDTLS_CONFIG_FILE)
#include "../../../../mbedtls/include/mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#include "../../../../mbedtls/include/mbedtls/net.h"
#include "../../../../mbedtls/include/mbedtls/ssl.h"
#include "../../../../mbedtls/include/mbedtls/certs.h"
#include "../../../../mbedtls/include/mbedtls/entropy.h"
#include "../../../../mbedtls/include/mbedtls/ctr_drbg.h"
#include "../../../../mbedtls/include/mbedtls/platform.h"
#include "../../../../mbedtls/include/mbedtls/error.h"


#define DEBUG_LEVEL 0
#if defined(MBEDTLS_DEBUG_C) && DEBUG_LEVEL > 0
#include "../../../../mbedtls/include/mbedtls/debug.h"
#endif

#if defined(_WIN32) || defined(__MINGW32__)
typedef int ssize_t;
#endif  // defined(_WIN32) || defined(__MINGW32__)

#if defined(_WIN32)
typedef int sock_size_t;

static inline int poll(struct pollfd *pfd, int nfds,
                       int timeout) { return WSAPoll ( pfd, nfds, timeout ); }
#else
#include <sys/poll.h>
typedef int SOCKET;
typedef size_t sock_size_t;
const int INVALID_SOCKET = -1;
#endif  // defined(_WIN32)

#if defined(MBEDTLS_DEBUG_C) && DEBUG_LEVEL > 0
/**
 * Debug callback for mbedtls
 */
static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
  const char *p, *basename;
  (void) ctx;

  /* Extract basename from file */
  for (p = basename = file; *p != '\0'; p++) {
    if (*p == '/' || *p == '\\') {
      basename = p + 1;
    }
  }
  mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
}
#endif
/**
 *
 * Pretty print error codes thrown by mbedtls
 */
static void print_err(int error_code) {
  const size_t LEN = 2048;
  char err_buf[LEN];
  mbedtls_strerror(error_code, err_buf, LEN);
  mbedtls_printf(" ERROR: %s\n", err_buf);
}

namespace rabit {
namespace utils {
/*! \brief data structure for network address */
struct SockAddr {
  sockaddr_in addr;
  // constructor
  SockAddr(void) {}
  SockAddr(const char *url, int port) {
    this->Set(url, port);
  }
  inline static std::string GetHostName(void) {
    std::string buf; buf.resize(256);
    utils::Check(gethostname(&buf[0], 256) != -1, "fail to get host name");
    return std::string(buf.c_str());
  }
  /*!
   * \brief set the address
   * \param url the url of the address
   * \param port the port of address
   */
  inline void Set(const char *host, int port) {
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_protocol = SOCK_STREAM;
    addrinfo *res = NULL;
    int sig = getaddrinfo(host, NULL, &hints, &res);
    Check(sig == 0 && res != NULL, "cannot obtain address of %s", host);
    Check(res->ai_family == AF_INET, "Does not support IPv6");
    memcpy(&addr, res->ai_addr, res->ai_addrlen);
    addr.sin_port = htons(port);
    freeaddrinfo(res);
  }
  /*! \brief return port of the address*/
  inline int port(void) const {
    return ntohs(addr.sin_port);
  }
  /*! \return a string representation of the address */
  inline std::string AddrStr(void) const {
    std::string buf; buf.resize(256);
#ifdef _WIN32
    const char *s = inet_ntop(AF_INET, (PVOID)&addr.sin_addr,
                    &buf[0], buf.length());
#else
    const char *s = inet_ntop(AF_INET, &addr.sin_addr,
                              &buf[0], buf.length());
#endif  // _WIN32
    Assert(s != NULL, "cannot decode address");
    return std::string(s);
  }
};

/*!
 * \brief base class containing common operations of TCP and UDP sockets
 */
class Socket {
 public:
  /*! \brief the TLS wrapper of a socket */
  mbedtls_net_context server_fd;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
  mbedtls_entropy_context entropy;
  bool created;
  // default conversion to mbedtls context
  inline operator mbedtls_net_context() const {
    return server_fd;
  }
  // default conversion to int
  inline operator SOCKET() const {
    return server_fd.fd;
  }
  /*!
   * \return last error of socket operation
   */
  inline static int GetLastError(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif  // _WIN32
  }
  /*! \return whether last error was would block */
  inline static bool LastErrorWouldBlock(void) {
    int errsv = GetLastError();
#ifdef _WIN32
    return errsv == WSAEWOULDBLOCK;
#else
    return errsv == EAGAIN || errsv == EWOULDBLOCK;
#endif  // _WIN32
  }
  /*!
   * \brief start up the socket module
   *   call this before using the sockets
   */
  inline static void Startup(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == -1) {
    Socket::Error("Startup");
    }
    if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2) {
    WSACleanup();
    utils::Error("Could not find a usable version of Winsock.dll\n");
    }
#endif  // _WIN32
  }
  /*!
   * \brief shutdown the socket module after use, all sockets need to be closed
   */
  inline static void Finalize(void) {
#ifdef _WIN32
    WSACleanup();
#endif  // _WIN32
  }
  /*!
   * \brief set this socket to use non-blocking mode
   * \param non_block whether set it to be non-block, if it is false
   *        it will set it back to block mode
   */
  inline void SetNonBlock(bool non_block) {
#ifdef _WIN32
    u_long mode = non_block ? 1 : 0;
    if (ioctlsocket(server_fd, FIONBIO, &mode) != NO_ERROR) {
      Socket::Error("SetNonBlock");
    }
#else
    if (!non_block) {
      mbedtls_net_set_block(&server_fd);
    } else {
      mbedtls_net_set_nonblock(&server_fd);
    }
#endif  // _WIN32
  }
  /*!
   * \brief try bind the socket to host, from start_port to end_port
   * \param start_port starting port number to try
   * \param end_port ending port number to try
   * \return the port successfully bind to, return -1 if failed to bind any port
   */
  inline int TryBindHost(int start_port, int end_port) {
    // TODO(tqchen) add prefix check
    for (int port = start_port; port < end_port; ++port) {
      if (mbedtls_net_bind(&server_fd, "0.0.0.0", std::to_string(port).c_str(), MBEDTLS_NET_PROTO_TCP) == 0) {
        return port;
      }
#if defined(_WIN32)
      if (WSAGetLastError() != WSAEADDRINUSE) {
        Socket::Error("TryBindHost");
      }
#else
      if (errno != EADDRINUSE) {
        Socket::Error("TryBindHost");
      }
#endif  // defined(_WIN32)
    }

    return -1;
  }
  /*! \brief get last error code if any */
  inline int GetSockError(void) const {
    int error = 0;
    socklen_t len = sizeof(error);
    if (server_fd.fd != INVALID_SOCKET && getsockopt(server_fd.fd,  SOL_SOCKET, SO_ERROR,
            reinterpret_cast<char*>(&error), &len) != 0) {
      Error("GetSockError");
    }
    return error;
  }
  /*! \brief check if anything bad happens */
  inline bool BadSocket(void) const {
    if (IsClosed()) return true;
    int err = GetSockError();
    return err == EBADF || err == EINTR;
  }
  /*! \brief check if socket is already closed */
  inline bool IsClosed(void) const {
    return !created;
  }
  /*! \brief close the socket */
  inline void Close(void) {
    if (created) {
#ifdef _WIN32
      closesocket(server_fd);
#else
      mbedtls_net_free(&server_fd);
      mbedtls_ssl_free(&ssl);
      mbedtls_ssl_config_free(&conf);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
#endif
      server_fd.fd = INVALID_SOCKET;
      created = false;
    } else {
      Error("Socket::Close double close the socket or close without create");
    }
  }
  // report an socket error
  inline static void Error(const char *msg) {
    int errsv = GetLastError();
#ifdef _WIN32
    utils::Error("Socket %s Error:WSAError-code=%d", msg, errsv);
#else
    utils::Error("Socket %s Error:%s\n", msg, strerror(errsv));
#endif
  }
};

/*!
 * \brief a wrapper of TCP socket that hopefully be cross platform
 */
class TCPSocket : public Socket {

  int ret;

 public:
  TCPSocket(void) {
    created = false;
    this->Create();
  }
  explicit TCPSocket(SOCKET sockfd) {
    created = false;
    this->Create();
    server_fd.fd = sockfd;
  }
  /*!
   * \brief enable/disable TCP keepalive
   * \param keepalive whether to set the keep alive option on
   */
  void SetKeepAlive(bool keepalive) {
    int opt = static_cast<int>(keepalive);
    if (server_fd.fd != INVALID_SOCKET && setsockopt(server_fd.fd, SOL_SOCKET, SO_KEEPALIVE,
                   reinterpret_cast<char*>(&opt), sizeof(opt)) < 0) {
      Socket::Error("SetKeepAlive");
    }
  }
  inline void SetLinger(int timeout = 0) {
    struct linger sl;
    sl.l_onoff = 1;    /* non-zero value enables linger option in kernel */
    sl.l_linger = timeout;    /* timeout interval in seconds */
    if (server_fd.fd != INVALID_SOCKET &&
                    setsockopt(server_fd.fd, SOL_SOCKET, SO_LINGER, reinterpret_cast<char*>(&sl), sizeof(sl)) == -1) {
      Socket::Error("SO_LINGER");
    }
  }
  /*!
   * \brief create the socket, call this before using socket
   * \param af domain
   */
  inline void Create(int af = PF_INET) {
    // initialize all mbedTLS contexts
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    created = true;
    // seeds and sets up entropy source
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
      print_err(ret);
      Socket::Error("Error: CTR_DRBG entropy source could not be seeded");
    }
  }
  /*!
   * \brief perform listen of the socket
   * \param backlog backlog parameter
   */
  inline void Listen(int backlog = 16) {
    listen(server_fd.fd, backlog);
  }
  /*! \brief get a new connection */
  TCPSocket Accept(void) {
    SOCKET newfd = accept(server_fd.fd, NULL, NULL);
    if (newfd == INVALID_SOCKET) {
      Socket::Error("Accept");
    }
    return TCPSocket(newfd);
  }
  /*!
   * \brief decide whether the socket is at OOB mark
   * \return 1 if at mark, 0 if not, -1 if an error occured
   */
  inline int AtMark(void) const {
#ifdef _WIN32
    unsigned long atmark;  // NOLINT(*)
    if (ioctlsocket(server_fd, SIOCATMARK, &atmark) != NO_ERROR) return -1;
#else
    int atmark;
    if (server_fd.fd != INVALID_SOCKET && ioctl(server_fd.fd, SIOCATMARK, &atmark) == -1) return -1;
#endif  // _WIN32
    return atmark;
  }
  /*!
   * \brief connect to an address
   * \param addr the address to connect to
   * \return whether connect is successful
   */
  inline bool Connect(const SockAddr &addr) {
    // Connect
    if ((ret = mbedtls_net_connect(&server_fd, addr.AddrStr().c_str(),
        std::to_string(addr.port()).c_str(), MBEDTLS_NET_PROTO_TCP)) != 0) {
      print_err(ret);
      Socket::Error("Error: Could not connect");
    }
    // configure TLS layer
    if ((ret = mbedtls_ssl_config_defaults(&conf,
        MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
      print_err(ret);
      Socket::Error("Error: Could not configure TLS layer");
    }

    // no certificate auth required (CHANGE FOR COMPLETE VERSION)
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

    // configure RNG
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // enable debugging
#if defined(MBEDTLS_DEBUG_C) && DEBUG_LEVEL > 0
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    // set up SSL context
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
      print_err(ret);
      Socket::Error("Error: could not set up SSL");
    }

    // configure hostname
    if ((ret = mbedtls_ssl_set_hostname(&ssl, addr.AddrStr().c_str())) != 0) {
      print_err(ret);
      Socket::Error("Error: Could not set hostname");
    }
    // configure input/output functions for sending data
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // perform handshake
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        print_err(ret);
        Socket::Error("Error: Failed handshake");
      }
    }
    return true;
  }
  /*!
   * \brief send data using the socket
   * \param buf the pointer to the buffer
   * \param len the size of the buffer
   * \param flags extra flags
   * \return size of data actually sent
   *         return -1 if error occurs
   */
  inline ssize_t Send(const void *buf_, size_t len, int flag = 0) {
    const unsigned char *buf = reinterpret_cast<const unsigned char*>(buf_);
    ret = mbedtls_ssl_write(&ssl, buf, len);
    if (ret < 0) {
      print_err(ret);
      Socket::Error("Error: Sending");
    }
    return ret;
  }
  /*!
   * \brief receive data using the socket
   * \param buf_ the pointer to the buffer
   * \param len the size of the buffer
   * \param flags extra flags
   * \return size of data actually received
   *         return -1 if error occurs
   */
  inline ssize_t Recv(void *buf_, size_t len, int flags = 0) {
    unsigned char *buf = reinterpret_cast<unsigned char*>(buf_);
    ret = mbedtls_ssl_read(&ssl, buf, len);
    if (ret < 0) {
      print_err(ret);
      Socket::Error("Error: Receiving");
    }
    return ret;
  }
  /*!
   * \brief peform block write that will attempt to send all data out
   *    can still return smaller than request when error occurs
   * \param buf the pointer to the buffer
   * \param len the size of the buffer
   * \return size of data actually sent
   */
  inline size_t SendAll(const void *buf_, size_t len) {
    const unsigned char *buf = reinterpret_cast<const unsigned char*>(buf_);
    size_t ndone = 0;
    while (ndone < len) {
      ret = mbedtls_ssl_write(&ssl, buf, static_cast<size_t>(len - ndone));
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
        if (LastErrorWouldBlock()) return ndone;
        print_err(ret);
        Socket::Error("Error: SendAll");
      }
      buf += ret;
      ndone += ret;
    }
    return ndone;
  }
  /*!
   * \brief peforma block read that will attempt to read all data
   *    can still return smaller than request when error occurs
   * \param buf_ the buffer pointer
   * \param len length of data to recv
   * \return size of data actually sent
   */
  inline size_t RecvAll(void *buf_, size_t len) {
    unsigned char *buf = reinterpret_cast<unsigned char*>(buf_);
    size_t ndone = 0;
    while (ndone < len) {
      mbedtls_printf("pid: %d ndone: %d len: %d. before ssl_read\n", getpid(), ndone, len);
      ret = mbedtls_ssl_read(&ssl, buf, static_cast<size_t>(len - ndone));
      mbedtls_printf("pid: %d ndone: %d len: %d ret: %d. after ssl_read\n", getpid(), ndone, len, ret);
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
        print_err(ret);
        if (LastErrorWouldBlock()) return ndone;
        print_err(ret);
        Socket::Error("Error: RecvAll");
      }
      if (ret == 0) return ndone;
      buf += ret;
      ndone += ret;
    }
    return ndone;
  }
  /*!
   * \brief send a string over network
   * \param str the string to be sent
   */
  inline void SendStr(const std::string &str) {
    int len = static_cast<int>(str.length());
    utils::Assert(this->SendAll(&len, sizeof(len)) == sizeof(len),
                  "error during send SendStr");
    if (len != 0) {
      utils::Assert(this->SendAll(str.c_str(), str.length()) == str.length(),
                    "error during send SendStr");
    }
  }
  /*!
   * \brief recv a string from network
   * \param out_str the string to receive
   */
  inline void RecvStr(std::string *out_str) {
    int len;
    utils::Assert(this->RecvAll(&len, sizeof(len)) == sizeof(len),
                  "error during send RecvStr");
    out_str->resize(len);
    if (len != 0) {
      utils::Assert(this->RecvAll(&(*out_str)[0], len) == out_str->length(),
                    "error during send SendStr");
    }
  }
};

/*! \brief helper data structure to perform poll */
struct PollHelper {
 public:
  /*!
   * \brief add file descriptor to watch for read
   * \param fd file descriptor to be watched
   */
  inline void WatchRead(SOCKET fd) {
    auto& pfd = fds[fd];
    pfd.fd = fd;
    pfd.events |= POLLIN;
  }
  /*!
   * \brief add file descriptor to watch for write
   * \param fd file descriptor to be watched
   */
  inline void WatchWrite(SOCKET fd) {
    auto& pfd = fds[fd];
    pfd.fd = fd;
    pfd.events |= POLLOUT;
  }
  /*!
   * \brief add file descriptor to watch for exception
   * \param fd file descriptor to be watched
   */
  inline void WatchException(SOCKET fd) {
    auto& pfd = fds[fd];
    pfd.fd = fd;
    pfd.events |= POLLPRI;
  }
  /*!
   * \brief Check if the descriptor is ready for read
   * \param fd file descriptor to check status
   */
  inline bool CheckRead(SOCKET fd) const {
    const auto& pfd = fds.find(fd);
    return pfd != fds.end() && ((pfd->second.events & POLLIN) != 0);
  }
  /*!
   * \brief Check if the descriptor is ready for write
   * \param fd file descriptor to check status
   */
  inline bool CheckWrite(SOCKET fd) const {
    const auto& pfd = fds.find(fd);
    return pfd != fds.end() && ((pfd->second.events & POLLOUT) != 0);
  }
  /*!
   * \brief Check if the descriptor has any exception
   * \param fd file descriptor to check status
   */
  inline bool CheckExcept(SOCKET fd) const {
    const auto& pfd = fds.find(fd);
    return pfd != fds.end() && ((pfd->second.events & POLLPRI) != 0);
  }
  /*!
   * \brief wait for exception event on a single descriptor
   * \param fd the file descriptor to wait the event for
   * \param timeout the timeout counter, can be negative, which means wait until the event happen
   * \return 1 if success, 0 if timeout, and -1 if error occurs
   */
  inline static int WaitExcept(SOCKET fd, long timeout = -1) { // NOLINT(*)
    pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLPRI;
    return poll(&pfd, 1, timeout);
  }

  /*!
   * \brief peform poll on the set defined, read, write, exception
   * \param timeout specify timeout in milliseconds(ms) if negative, means poll will block
   * \return
   */
  inline void Poll(long timeout = -1) {  // NOLINT(*)
    std::vector<pollfd> fdset;
    fdset.reserve(fds.size());
    for (auto kv : fds) {
      fdset.push_back(kv.second);
    }
    int ret = poll(fdset.data(), fdset.size(), timeout);
    if (ret == -1) {
      Socket::Error("Poll");
    } else {
      for (auto& pfd : fdset) {
        auto revents = pfd.revents & pfd.events;
        if (!revents) {
          fds.erase(pfd.fd);
        } else {
          fds[pfd.fd].events = revents;
        }
      }
    }
  }

  std::unordered_map<SOCKET, pollfd> fds;
};
}  // namespace utils
}  // namespace rabit
#endif  // RABIT_INTERNAL_SOCKET_H_
