#ifndef SOCKET_HH
#define SOCKET_HH

#include <string>
#include <ctime>
#include <sstream>
#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include "logging.hh"

enum { TLS_VERSION_1_0 = 0x00000001,
       TLS_VERSION_1_1 = 0x00000002,
       TLS_VERSION_1_2 = 0x00000004
};

typedef unsigned short Port;

enum { SOCK_ERR = -1, SOCK_SSLERR = -2, SOCK_AGAIN = -3, SOCK_OK = 0 };

class InetSockAddrIn : public sockaddr_in
{
public:
  InetSockAddrIn() { init(0, 0); }
  InetSockAddrIn(unsigned long int address, Port port);
  InetSockAddrIn(Port port);
  InetSockAddrIn(const char *address, Port port);
  InetSockAddrIn(const in_addr &address, Port port);

  std::string s() const;
  std::string unparse() const { return s(); }
  Port get_port()  const { return ntohs(sin_port); }
  unsigned long ip() const { return sin_addr.s_addr; }

  operator bool() const { return ip() && sin_port != 0; }

private:
  void init(unsigned long int address, Port port);
}; 

// StreamSocket class is an interface abstraction for a socket and a connection
class StreamSocket
{
public:
  StreamSocket(int fd = -1) : _fd(fd), _is_bound(false) {};
  virtual ~StreamSocket() {};
  
  virtual int get_error();

  virtual int create() = 0;

  virtual int bind(const InetSockAddrIn &address);
  virtual int bind(const unsigned long int address, const Port port) {
    InetSockAddrIn addr(address, port); return bind(addr); };
  virtual int bind(const Port port) {
    InetSockAddrIn addr(port); return bind(addr); };

  virtual int read(void* c, size_t len) = 0;
  virtual int peek(void* c, size_t len) = 0;
  virtual int write(const void *c, size_t len) = 0;

  virtual int recvfrom(void*, size_t, struct sockaddr *, socklen_t *,
		       int = 0) = 0;
  virtual int sendto(const void*, size_t, const struct sockaddr *,
		     const socklen_t, int = 0) = 0;

  // A StreamSocket may periodically need activity unrelated to 
  // application data (for example, SSL handshakes).  When 
  // need_{read,write} is true the application should select for 
  // {read,writ}ability and call proceed when the condition is true.
  virtual bool ready() { return true; }
  virtual bool need_read() { return false; }
  virtual bool need_write() { return false; }
  virtual int  proceed() { return SOCK_OK; }

  virtual int listen() = 0;
  virtual int listen(const InetSockAddrIn &addr) = 0;
  
  virtual int connect(const InetSockAddrIn &address) = 0;
  virtual int connect_post() { return 0; }
  virtual int close() = 0;

  // accepts an incoming connection and returns a _new_ StreamSocket
  // associated with this connection. To delete this new StreamSocket
  // object is the client's resposibility
  virtual int accept(StreamSocket *&, struct sockaddr *, socklen_t *) = 0;
  virtual int accept(StreamSocket *&) = 0;
  
  virtual operator bool() { return _fd != -1; }
  virtual int fd() const { return _fd; }
  virtual InetSockAddrIn get_name() const = 0;
  virtual InetSockAddrIn get_peer() const = 0;

  virtual bool is_connected() { return bool(*this); }
  virtual bool is_listening() const = 0;

  std::string unparse() const { return s(); }
  virtual const std::string s() const { return classname(); }
  virtual const std::string classname() const { return "socket"; }
  
protected:
  int _fd;
  mutable bool _is_bound;
  InetSockAddrIn _name;
  InetSockAddrIn _peer;

  void err_sys(const char *message) const;

  virtual int select_read(int sec, int usec);
  virtual int select_write(int sec, int usec);
  virtual int select_exception(int sec, int usec);
  static const std::string socket_fd_peer(const std::string classname, const int fd,
    //const InetSockAddrIn &peer) { return classname + "(" + std::string(fd) + (peer ? "<-" + peer.s() : "") + ")"; }
    const InetSockAddrIn &peer) //{ return classname + "(" + fd + (peer ? "<-" + peer.s() : "") + ")"; }
  {
    std::ostringstream s;
    s << classname << "(" << fd
      << (peer ? "<-" + peer.s() : "")
      << ")";
    return s.str();
  }
};

// INETSocket is an implementation of StreamSocket interface with INET
// sockets. Or you can view it as a thin wrapper over some of socket API,
// if you want, though this would not be a conceptual view.
class INETSocket : public StreamSocket
{
public:
  INETSocket(int fd = -1, InetSockAddrIn *peer = NULL);
  virtual ~INETSocket();
  virtual INETSocket &operator=(const INETSocket &x);

  // Finish asynchronous connect().
  virtual int proceed() {
    return (_conn_state == IN_PROGRESS) ? connect(InetSockAddrIn()) : SOCK_OK; }
  virtual bool need_write() { return (_conn_state == IN_PROGRESS); }

  virtual int listen();
  int listen(unsigned long int address, Port port);
  int listen(Port port);
  virtual int listen(const InetSockAddrIn &addr);
  
  virtual int connect(const InetSockAddrIn &address);
  virtual int close();
  virtual int accept(StreamSocket *&, struct sockaddr *, socklen_t *);
  virtual int accept(StreamSocket *&);
  
  virtual InetSockAddrIn get_name() const;
  virtual InetSockAddrIn get_peer() const { return _peer; };
    
  virtual bool is_connected();
  virtual bool is_listening() const { return _is_listening; }

  virtual const std::string s() const { return socket_fd_peer(classname(),_fd,_peer); }
  virtual const std::string classname() const { return "INETSocket"; }

protected:
  enum { DISCONNECTED=0, IN_PROGRESS, 
	 IN_PROGRESS_SSL, ESTABLISHED } _conn_state;
  bool _is_listening;

  virtual int create();
  virtual int read(void* c, size_t len);
  virtual int peek(void* c, size_t len);
  virtual int write(const void *c, size_t len);

  virtual int recvfrom(void* __attribute__ ((unused)),
		       size_t __attribute__ ((unused)),
		       struct sockaddr * __attribute__ ((unused)),
		       socklen_t * __attribute__ ((unused)),
		       int __attribute__ ((unused)) = 0)
  { return SOCK_ERR; };
  virtual int sendto(const void * __attribute__ ((unused)),
		     size_t __attribute__ ((unused)),
		     const struct sockaddr * __attribute__ ((unused)),
		     const socklen_t __attribute__ ((unused)),
		     int __attribute__ ((unused)) = 0)
  { return SOCK_ERR; };
};

class SSLContext
{
public:
  enum EncryptionType { STRONGEST = 0, NONE = 1, LOW = 2, AESNI = 3,
			__DEFAULT = STRONGEST,
			__FIRST = STRONGEST, __LAST = AESNI };

  SSLContext(const std::string& certfile, const std::string& trusted_dir,
	     const bool is_client = false,
	     const enum EncryptionType enc_type = __DEFAULT,
	     int verify_mode = default_verify_mode,
	     int (*verify_callback)(int, X509_STORE_CTX *) = 0,
	     const std::string& keyfile = std::string());
  SSLContext(const SSLContext& x)
    : _certfile(x._certfile), _keyfile(x._keyfile), _trusted_dir(x._trusted_dir),
      _is_client(x._is_client), _enc_type(x._enc_type), _ctx(0),
      _verify_mode(x._verify_mode), _verify_callback(x._verify_callback),
      _enable_sslv3(x._enable_sslv3), _tls_version(x._tls_version) {}
  ~SSLContext() { free_ctx(); }
  SSLContext &operator=(const SSLContext&);

  // SSL_CTX* is ref-counted. Its consumer, SSL_new(), adds a reference.
  SSL_CTX* new_ctx();
  SSL_CTX* get_ctx() { if (0 == _ctx) return new_ctx(); else return _ctx; }

  const std::string certfile() const { return _certfile; }
  const std::string keyfile() const { return _keyfile; }
  const std::string trusted_dir() const { return _trusted_dir; }
  int encryption_type() const { return _enc_type; }

  std::string get_ciphers() const;
  std::string unparse() const;

  static std::string unparse_ciphers(STACK_OF(SSL_CIPHER) *);

  static const int default_verify_mode;
  static const int max_verify_depth;

private:
  std::string _certfile;
  std::string _keyfile;
  std::string _trusted_dir;
  bool _is_client;
  int _enc_type;
  SSL_CTX *_ctx;
  int _verify_mode;
  int (*_verify_callback)(int, X509_STORE_CTX *);
  bool _enable_sslv3;
  uint32_t _tls_version;

  void free_ctx();

  static BIO *bio_err;
};

class SSLSocket : public INETSocket 
{
private:
  typedef INETSocket inherited;

public:
  SSLSocket(const SSLContext &context, SSL *ssl = 0, int fd = -1,
	    bool accepting = false, bool ssl_error = false,
	    InetSockAddrIn *peer = NULL);
  virtual ~SSLSocket();

  virtual int connect(const InetSockAddrIn &address);
  virtual int accept(StreamSocket *&, struct sockaddr *, socklen_t *);
  virtual int proceed();
  virtual bool read() { return _accepting; }
  virtual bool need_read() {
    return _ssl && SSL_get_shutdown(_ssl) == 0 && SSL_want_read(_ssl); }
  virtual bool need_write() {
    if (_conn_state == IN_PROGRESS) return true;
    return _ssl && SSL_get_shutdown(_ssl) == 0 && SSL_want_write(_ssl); }
  virtual int close(); 

  virtual const std::string classname() const { return std::string("SSLSocket"); }

  virtual const SSLContext& get_context() const { return _context; }
  SSL *get_ssl() { return _ssl; }

  static std::string get_session_ciphers(SSL *);

  // sometimes SSL functions have an extra return code to use when
  // gathering error information and sometimes they don't.
  static std::string get_ssl_err();
  static void err_ssl(const std::string socket, const char *message, std::ostringstream &sa);
  static void err_ssl(const std::string socket, const char *message, int err, std::ostringstream &sa);
  static void err_ssl(const SSLSocket *s, const char *message, std::ostringstream &sa);
  static void err_ssl(const SSLSocket *s, const char *message, int err, std::ostringstream &sa);

  virtual void audit_ssl_connection(const InetSockAddrIn &address, std::string conn_msg, std::string err_str, bool success);

  virtual int write(const void *c, size_t len);

private:
  SSLSocket &operator=(const SSLSocket &); // hidden

  virtual int read(void* c, size_t len);
  virtual int peek(void* c, size_t len);
//  virtual int write(const void *c, size_t len);

  void shutdown();

  static std::string get_cipher_info(SSL *ssl);

  SSLContext _context; 
  SSL *_ssl;
  bool _accepting;
  bool _ssl_error;
};

// InetDGSocket is an implementation of StreamSocket interface with INET
// sockets.
class InetDGSocket : public StreamSocket
{
private:
  typedef StreamSocket inherited;

public:
  InetDGSocket(int fd = -1);
  virtual ~InetDGSocket();
  virtual InetDGSocket &operator=(const InetDGSocket &x);

  virtual int read(void* __attribute__ ((unused)),
		   size_t __attribute__ ((unused))) { return SOCK_ERR; };
  virtual int peek(void* __attribute__ ((unused)),
		   size_t __attribute__ ((unused))) { return SOCK_ERR; };
  virtual int write(const void *__attribute__ ((unused)),
		    size_t __attribute__ ((unused))) { return SOCK_ERR; };
  virtual int listen() { return SOCK_ERR; };
  virtual int listen(const InetSockAddrIn& __attribute__ ((unused))) {
    return SOCK_ERR; };
  virtual int connect(const InetSockAddrIn& __attribute__ ((unused))) {
    return SOCK_ERR; };
  virtual int accept(StreamSocket *& __attribute__ ((unused)),
		     struct sockaddr * __attribute__ ((unused)),
		     socklen_t * __attribute__ ((unused))) { return SOCK_ERR; };
  virtual int accept(StreamSocket *& __attribute__ ((unused))) {
    return SOCK_ERR; };
  virtual InetSockAddrIn get_name() const { return _name; };
  virtual InetSockAddrIn get_peer() const { return _peer; };
  virtual bool is_connected() { return false; }
  virtual bool is_listening() const { return false; }

  virtual int recvfrom(void*, size_t, struct sockaddr *, socklen_t *,
		       int = 0);
  virtual int sendto(const void *, size_t, const struct sockaddr *,
		     const socklen_t, int = 0);
  int recvfrom(void* c, size_t len, InetSockAddrIn &peer, int flags = 0);
  int sendto(const void *c, size_t len, const InetSockAddrIn &peer,
	     int flags = 0);

  virtual const std::string s() const
  {
    std::ostringstream s;
    s << "InetDGSocket(" << _fd << ")";
    return s.str();
  }

private:
  virtual int create();
  virtual int close();
};

#endif
