// -*- related-file-name: "../../include/mazu/socket.hh" -*-

#include <assert.h>
#include <fcntl.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include "socket.hh"

InetSockAddrIn::InetSockAddrIn(unsigned long int address, Port port)
{
  init(address, port);
}

InetSockAddrIn::InetSockAddrIn(Port port) 
{
  init(INADDR_ANY, port);
}

InetSockAddrIn::InetSockAddrIn(const char *address, Port port)
{
  assert(address);

  init(0, port);
  if (inet_pton(AF_INET, address, &sin_addr) <= 0) {
    { /* too bad */ }
  }
} 


InetSockAddrIn::InetSockAddrIn(const in_addr &address, Port port)
{
  memset(this, 0, sizeof(*this));
    
  sin_family = AF_INET;
  sin_addr = address;
  sin_port = htons(port);
}    

std::string
InetSockAddrIn::s() const
{
  char buffer[INET_ADDRSTRLEN];

  const char *s = inet_ntop(AF_INET, &sin_addr, buffer, sizeof(buffer)-1);
  if (s == NULL)
    return std::string();

  std::ostringstream sa;
  sa << s << ":" << get_port();
  return sa.str();
}

void
InetSockAddrIn::init(unsigned long int address, Port port)
{
  memset(this, 0, sizeof(*this));
    
  sin_family = AF_INET;
  sin_addr.s_addr = htonl(address);
  sin_port = htons(port);
}    

///////////////////////// class StreamSocket ////////////////////

void
StreamSocket::err_sys(const char *message) const
{
  ERRORF("%s: %s", message, unparse().c_str());
}

int
StreamSocket::get_error()
{
  int so_errno;
  socklen_t optlen = sizeof(so_errno);

  int r = getsockopt(_fd, SOL_SOCKET, SO_ERROR, &so_errno, &optlen);
  if (r < 0) {
    err_sys("getsockopt");
    return r;
  }
  
  return so_errno;
}

int
StreamSocket::bind(const InetSockAddrIn &address)
{
  if (::bind(_fd, (sockaddr*)&address, sizeof(address)) < 0) {
    err_sys((std::string("Bind error (") + address.s() + ")").c_str());
    return -1;
  }
  socklen_t namelen = sizeof(_name);
  if (::getsockname(_fd, (struct sockaddr *)&_name, &namelen) < 0) {
    err_sys("StreamSocket: getsockname() failed");
    return -1;
  }
  _is_bound = true;
  INFOF("Succesfully bound to %s", _name.s().c_str());
  return 0;
}

int
StreamSocket::select_read(int sec, int usec)
{
  if (_fd < 0) {
    errno = EBADF;
    return -1;
  }

  struct timeval tv;
  tv.tv_sec = sec;
  tv.tv_usec = usec;

  fd_set waitfor;
  FD_ZERO(&waitfor);
  FD_SET(_fd, &waitfor);

  int r = ::select(_fd + 1, &waitfor, NULL, NULL, &tv);
  DEBUG2F("%s::select_read returing %d", s().c_str(), r);
  return r;
}

int
StreamSocket::select_write(int sec, int usec)
{
  if (_fd < 0) {
    errno = EBADF;
    return -1;
  }

  struct timeval tv;
  tv.tv_sec = sec;
  tv.tv_usec = usec;

  fd_set waitfor;
  FD_ZERO(&waitfor);
  FD_SET(_fd, &waitfor);

  int r = ::select(_fd + 1, NULL, &waitfor, NULL, &tv);
  DEBUG2F("%s::select_write returing %d", s().c_str(), r);
  return r;
}

int
StreamSocket::select_exception(int sec, int usec)
{
  if (_fd < 0) {
    errno = EBADF;
    return -1;
  }

  struct timeval tv;
  tv.tv_sec = sec;
  tv.tv_usec = usec;

  fd_set waitfor;
  FD_ZERO(&waitfor);
  FD_SET(_fd, &waitfor);

  return ::select(_fd + 1, NULL, NULL, &waitfor, &tv);
}

///////////////////////// class INETSocket ////////////////////

INETSocket::INETSocket(int fd, InetSockAddrIn *peer)
  : StreamSocket(fd), _is_listening(false)
{
  if (peer) _peer=*peer;
  if (fd == -1)
    create();
  else
    _conn_state = ESTABLISHED;
}

INETSocket::~INETSocket()
{
  close();
}

INETSocket &
INETSocket::operator=(const INETSocket &x)
{
  close();
  _fd = dup(x._fd);
  return *this;
}

int
INETSocket::create()
{
  _fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (_fd < 0) {
    err_sys("socket error");
    return -1;
  }

  if (fcntl(_fd, F_SETFL, O_NONBLOCK) < 0) {
    err_sys("fcntl error: failed to set O_NONBLOCK");
    return -1;
  }
  int fl = fcntl(_fd, F_GETFD, 0);
  if (fl < 0) {
    err_sys("fcntl error: F_GETFD failed");
    fl = 0;
  }
  fl |= FD_CLOEXEC;
  if (fcntl(_fd, F_SETFD, fl) < 0) {
    err_sys("fcntl error: failed to set FD_CLOEXEC");
    return -1;
  }

  int enable = 1;
  if (setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, 
		 (void *)&enable, sizeof(enable)) < 0)
    err_sys("setsockopt error: failed to set SO_REUSEADDR");
  if (setsockopt(_fd, SOL_SOCKET, SO_KEEPALIVE,
		 (void *)&enable, sizeof(enable)) < 0)
    err_sys("setsockopt error: failed to set SO_KEEPALIVE");

  _conn_state = DISCONNECTED;
  
  return 0;
}

int INETSocket::listen()
{
  if (::listen(_fd, 128) < 0) {
    err_sys("Listen error");
    return -1;
  }
  _is_listening = true;
  return 0;
}

int INETSocket::listen(unsigned long int address, Port port)
{
  int b = bind(address, port);
  if (b != 0)    
    return b;

  int r = listen();
  if (!r)
    _is_listening = true;
  return r;
}

int INETSocket::listen(const InetSockAddrIn &addr)
{
  int b = bind(addr);
  if (b != 0)    
    return b;

  int r = listen();
  if (!r)
    _is_listening = true;
  return r;
}

int INETSocket::listen(Port port)
{
  int b = bind(port);
  if (b != 0) 
    return b;

  int r = listen();
  if (!r)
    _is_listening = true;
  return r;
}

int
INETSocket::connect(const InetSockAddrIn &address)
{
  AT_MOST_ONCE_A_MINUTE
    (DEBUGF("INETSocket::connect to %s, state %d",
	   (address ? address.s().c_str() : _peer.s().c_str()), _conn_state));
  if (_conn_state == DISCONNECTED) {
    memcpy(&_peer, &address, sizeof(_peer));
    if (!::connect(_fd, (sockaddr *)&address, sizeof(sockaddr_in))) {
      _conn_state = ESTABLISHED;
      return SOCK_OK;
    }
    if (errno == EINPROGRESS) {
      _conn_state = IN_PROGRESS;
      return SOCK_AGAIN;
    }
    return SOCK_ERR;
  }

  if (_conn_state == IN_PROGRESS) {
    int v;
    socklen_t sv = sizeof(v);
    int r = getsockopt(_fd, SOL_SOCKET, SO_ERROR, &v, &sv);
    if (r < 0) {
      err_sys("INETSocket::connect: getsockopt failed");
      return SOCK_ERR;
    }
    if (v) {
      WARNINGF("INETSocket::connect(%s): connect failed (%d)",
	       s().c_str(), v);
      return SOCK_ERR;
    } else {
      _conn_state = ESTABLISHED;
      return SOCK_OK;
    }
  }
  ERRORF("INETSocket::connect (%s): socket is already connected", 
	 s().c_str());
  return SOCK_ERR;
}

bool
INETSocket::is_connected()
{
  return _conn_state == ESTABLISHED;
}

int
INETSocket::accept(StreamSocket *&s, struct sockaddr *addr, socklen_t *addrlen)
{
  InetSockAddrIn peer;
  socklen_t peerlen = sizeof(peer);
  int newfd = ::accept(_fd, (struct sockaddr *)&peer, &peerlen);
  if (newfd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return SOCK_AGAIN;
    err_sys("INETSocket::accept: failed");
    return SOCK_ERR;
  }
  if (addr && addrlen && *addrlen > 0) {
    memcpy(addr, &peer, (peerlen > *addrlen) ? *addrlen : peerlen);
    *addrlen = peerlen;
  }
  if (fcntl(newfd, F_SETFL, O_NONBLOCK) < 0) {
    err_sys("fcntl error");
    return SOCK_ERR;
  }
  s = new INETSocket(newfd,&peer);
  INFOF("%s: accepting %s", this->s().c_str(), s->s().c_str());
  return SOCK_OK;
}

int
INETSocket::accept(StreamSocket *&s)
{
  return accept(s, 0, 0);
}

InetSockAddrIn
INETSocket::get_name() const
{
  if (_is_bound)
    return _name;
  socklen_t namelen = sizeof(_name);
  if (::getsockname(_fd, (struct sockaddr *)&_name, &namelen) < 0) {
    err_sys("INETSocket: getsockname() failed");
    return InetSockAddrIn();
  }
  _is_bound = true;
  return _name;
}

int
INETSocket::read(void *c, size_t len)
{
  int r = ::read(_fd, (char*)c, len);
  if (r < 0) {
    if (errno == EAGAIN)
      return SOCK_AGAIN;
    err_sys("INETSocket::read: failed");
    return SOCK_ERR;
  }
  return r;
}

int
INETSocket::peek(void *c, size_t len)
{
  int r = ::recv(_fd, c, len, MSG_PEEK);
  if (r < 0) {
    if (errno == EAGAIN)
      return SOCK_AGAIN;
    err_sys("INETSocket::peek: failed");
    return SOCK_ERR;
  }
  return r;
}

int
INETSocket::write(const void *c, size_t len)
{
  int r = ::write(_fd, (const char*)c, len);
  if (r < 0) {
    if (errno == EAGAIN)
      return SOCK_AGAIN;
    err_sys("INETSocket::write: failed");
    return SOCK_ERR;
  }
  return r;
}

int
INETSocket::close()
{ 
  _conn_state = DISCONNECTED;
  if (_fd >= 0) {
    // Set _fd = -1 before closing. That way a thread waiting for the close
    // event will always see _fd == -1 when it wakes up, even if we have not
    // yet returned from the close().
    int r;
    int closing_fd = _fd;
    _fd = -1;
    if (::shutdown(closing_fd, SHUT_RDWR) != 0 && errno != ENOTCONN)
      err_sys("INETSocket::close: shutdown failed");
    if ((r = ::close(closing_fd)) != 0)
      err_sys("INETSocket::close: close failed");
    return r;
  }
  return 0;
}

///////////////////////// class InetDGSocket ////////////////////

InetDGSocket::InetDGSocket(int fd)
  : StreamSocket(fd)
{
  create();
}

InetDGSocket::~InetDGSocket()
{
  close();
}

InetDGSocket &
InetDGSocket::operator=(const InetDGSocket &x)
{
  close();
  _fd = dup(x._fd);
  return *this;
}

int InetDGSocket::create()
{
  _fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (_fd < 0) {
    err_sys("socket error");
    return -1;
  }

  if (fcntl(_fd, F_SETFL, O_NONBLOCK) < 0) {
    err_sys("fcntl error: failed to set O_NONBLOCK");
    return -1;
  }
  int fl = fcntl(_fd, F_GETFD, 0);
  if (fl < 0) {
    err_sys("fcntl error: F_GETFD failed");
    fl = 0;
  }
  fl |= FD_CLOEXEC;
  if (fcntl(_fd, F_SETFD, fl) < 0) {
    err_sys("fcntl error: failed to set FD_CLOEXEC");
    return -1;
  }

  int enable = 1;
  if (setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR,
		 (void *)&enable, sizeof(enable)) < 0)
    err_sys("setsockopt error: failed to set SO_REUSEADDR");

  return 0;
}

int InetDGSocket::close()
{
  if (_fd >= 0) {
    // Set _fd = -1 before closing. That way a thread waiting for the close
    // event will always see _fd == -1 when it wakes up, even if we have not
    // yet returned from the close().
    int r;
    int closing_fd = _fd;
    _fd = -1;
    if ((r = ::close(closing_fd)) != 0)
      err_sys("InetDGSocket::close: close failed");
    return r;
  }
  return 0;
}

int InetDGSocket::recvfrom(void* c, size_t len,
			   struct sockaddr *from, socklen_t *fromlen,
			   int flags)
{
  if (!_is_bound) {
    ERRORF("InetDGSocket::recvfrom(%s): socket is not bound", s().c_str());
    return SOCK_ERR;
  }
  int r = ::recvfrom(_fd, c, len, flags, from, fromlen);
  if (r < 0) {
    if (errno == EAGAIN)
      return SOCK_AGAIN;
    return SOCK_ERR;
  }
  memcpy(&_peer, from, (sizeof(_peer) < *fromlen) ? sizeof(_peer) : *fromlen);
  return r;
}

int InetDGSocket::sendto(const void *c, size_t len,
			 const struct sockaddr *to, const socklen_t tolen,
			 int flags)
{
  if (!_is_bound) {
    ERRORF("InetDGSocket::sendto(%s): socket is not bound", s().c_str());
    return SOCK_ERR;
  }
  int r = ::sendto(_fd, c, len, flags, to, tolen);
  if (r < 0) {
    if (errno == EAGAIN)
      return SOCK_AGAIN;
    err_sys("InetDGSocket::sendto: failed");
    return SOCK_ERR;
  }
  return r;
}

int InetDGSocket::recvfrom(void* c, size_t len, InetSockAddrIn &peer, int flags)
{
  InetSockAddrIn from;
  socklen_t fromlen = sizeof(from);
  int r = recvfrom(c, len, (struct sockaddr *)&from, &fromlen, flags);
  if (r >= 0) peer = from;
  return r;
}

int InetDGSocket::sendto(const void *c, size_t len, const InetSockAddrIn &peer,
			 int flags)
{
  return sendto(c, len, (struct sockaddr *)&peer, sizeof(peer), flags);
}
