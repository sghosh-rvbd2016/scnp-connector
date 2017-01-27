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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "socket.hh"

static const unsigned long NO_SHARED_CIPHER =
  ERR_PACK(ERR_LIB_SSL,0,SSL_R_NO_SHARED_CIPHER);
#define HAS_NO_SHARED_CIPHER \
  (NO_SHARED_CIPHER == (ERR_peek_last_error()&0xff000fff))

///////////////////////// class SSLContext ////////////////////

BIO *SSLContext::bio_err = 0;

const int
SSLContext::default_verify_mode =
  SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

const int
SSLContext::max_verify_depth = 10;


SSLContext::SSLContext(const std::string& certfile, const std::string& trusted_dir,
		       const bool is_client,
		       const enum EncryptionType enc_type,
		       int verify_mode,
		       int (*verify_callback)(int, X509_STORE_CTX *),
		       const std::string& keyfile)
  : _certfile(certfile), _keyfile(keyfile), _trusted_dir(trusted_dir),
    _is_client(is_client), _enc_type(enc_type), _ctx(0),
    _verify_mode(verify_mode), _verify_callback(verify_callback),
    _enable_sslv3(false),
    _tls_version(TLS_VERSION_1_1 | TLS_VERSION_1_2)
{
  if (!bio_err) {
    /* Global system initialization */
    OpenSSL_add_all_algorithms(); // Need this because SSL_library_init() is busted for FIPS!
    SSL_library_init();
    SSL_load_error_strings();

    /* An error write context */
    bio_err = BIO_new(BIO_s_mem());

    // Ignore SIGPIPE signal (broken pipe)
    struct sigaction act;
    memset(&act, 0, sizeof(act));

    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    int sar = sigaction(SIGPIPE, &act, NULL);
    if (sar < 0)
      ERRORF("SSLContext::SSLContext(): SIGPIPE %s", strerror(errno));
  }
  if (_keyfile.empty())
    _keyfile = _certfile;
}

SSLContext&
SSLContext::operator=(const SSLContext& x)
{
  if (this != &x) {
    _certfile = x._certfile;
    _keyfile = x._keyfile;
    _trusted_dir = x._trusted_dir;
    _is_client = x._is_client;
    _enc_type = x._enc_type;
    _verify_mode = x._verify_mode;
    _verify_callback = x._verify_callback;
    free_ctx();
  }
  return *this;
}

static int
def_verify_cb(int ok, X509_STORE_CTX *ctx)
{
  int err = X509_STORE_CTX_get_error(ctx);
  X509* err_cert = X509_STORE_CTX_get_current_cert(ctx);
  int depth = X509_STORE_CTX_get_error_depth(ctx);

  if (ok && depth > SSLContext::max_verify_depth) {
    ok = 0;
    err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
    X509_STORE_CTX_set_error(ctx, err);
  }

  if (!ok) {
    char subject[1024];
    X509_NAME_oneline(X509_get_subject_name(err_cert),
		      subject, sizeof(subject));
    ERRORF("Certificate@%d err=%d (%s) \"%s\"",
	   depth, err, X509_verify_cert_error_string(err), subject);
  }
  return ok;
}

SSL_CTX*
SSLContext::new_ctx()
{
  static enum { Unknown, Capable, NotCapable } aesni = Unknown;
  if (Unknown == aesni) {
#if (defined(__x86_64__) && SIZEOF_LONG == 8)
    // Test pclmulqdq (bit 33) and aes (bit 57) flags
    const unsigned long mask = (1ul<<33) | (1ul<<57);
    aesni = (mask == (OPENSSL_ia32cap & mask)) ? Capable : NotCapable;
#else
    aesni = NotCapable;
#endif
  }
  const SSL_METHOD *meth;
  std::ostringstream sa;
  free_ctx();

  if (_certfile.empty() && _keyfile.empty())
    return 0;
    
  /* Create our context*/
  meth = _is_client ? SSLv23_client_method() : SSLv23_server_method();
  if (!meth) {
    SSLSocket::err_ssl(0, "Couldn't create method", sa);
    return 0;
  }
  _ctx = SSL_CTX_new(meth);
  if (!_ctx) {
    SSLSocket::err_ssl(0, "Couldn't create context", sa);
    return 0;
  }

  // Disable compression
  SSL_CTX_set_options(_ctx, SSL_OP_NO_COMPRESSION);

  // Disable protocol(s)
  SSL_CTX_set_options(_ctx, SSL_OP_NO_SSLv2);
  if (FIPS_mode() || !_enable_sslv3)
    SSL_CTX_set_options(_ctx, SSL_OP_NO_SSLv3);
  if (!_is_client) {	// Server only
    if (0 == (_tls_version & TLS_VERSION_1_0))
      SSL_CTX_set_options(_ctx, SSL_OP_NO_TLSv1);
    if (0 == (_tls_version & TLS_VERSION_1_1))
      SSL_CTX_set_options(_ctx, SSL_OP_NO_TLSv1_1);
    if (0 == (_tls_version & TLS_VERSION_1_2))
      SSL_CTX_set_options(_ctx, SSL_OP_NO_TLSv1_2);
  }

  int rc = 0;
  if (FIPS_mode())
    rc = SSL_CTX_set_cipher_list(_ctx, "aRSA+AES:DES-CBC3-SHA:-AES128:@STRENGTH");
  else if (!_is_client) {
    // It turned out that the server's cipher list order (preferences) doesn't
    // matter for the cipher selection because we don't use
    // SSL_OP_CIPHER_SERVER_PREFERENCE option. See man SSL_CTX_set_options(3).
    // And we can NOT use SSL_OP_CIPHER_SERVER_PREFERENCE to support the
    // client's None/Weak encryption request. Therefore, we just use the
    // default with eNULL.
    // Note that starting with openssl-1.0.1m, SSL_DEFAULT_CIPHER_LIST
    // excludes EXPORT.
    if (0 == (_tls_version & TLS_VERSION_1_0))
      rc = SSL_CTX_set_cipher_list(_ctx,
				   "ALL:eNULL:!TLSv1:!EXPORT:!aNULL:!SSLv2:!NULL-MD5");
    else
      rc = SSL_CTX_set_cipher_list(_ctx,
				   "ALL:eNULL:!EXPORT:!aNULL:!SSLv2:!NULL-MD5");
  } else {
    switch (_enc_type) {
    case NONE:
      rc = SSL_CTX_set_cipher_list(_ctx,
				   "eNULL:@STRENGTH:ALL:!EXPORT:!aNULL:!SSLv2");
      break;
    case LOW:
      rc = SSL_CTX_set_cipher_list(_ctx, "RC4:" SSL_DEFAULT_CIPHER_LIST);
      break;
    case AESNI:
      if (Capable == aesni) {
	rc = SSL_CTX_set_cipher_list(_ctx, SSL_DEFAULT_CIPHER_LIST);
	break;
      }
      // Fall through
    case STRONGEST:
    default:
      // This is no longer the strongest.
      // AES256-SHA for the backward compatible performance.
      rc = SSL_CTX_set_cipher_list(_ctx,
				   "AES256-SHA:" SSL_DEFAULT_CIPHER_LIST);
      break;
    }
  }
  if (!rc) {
    SSLSocket::err_ssl(0, "Couldn't set cipher list", sa);
    SSL_CTX_set_cipher_list(_ctx, SSL_DEFAULT_CIPHER_LIST);
  }

  /* Load our keys and certificates*/
  if (!SSL_CTX_use_certificate_file(_ctx,
				    !_certfile.empty() ? _certfile.c_str() : 0,
				    SSL_FILETYPE_PEM))
    SSLSocket::err_ssl(0, "Couldn't read certificate file", sa);

  if (!SSL_CTX_use_PrivateKey_file(_ctx,
				   !_keyfile.empty() ? _keyfile.c_str() : 0,
				   SSL_FILETYPE_PEM))
    SSLSocket::err_ssl(0, "Couldn't read key file", sa);

  /* Load the CAs we trust */
  if (!SSL_CTX_load_verify_locations(_ctx,
				     !_certfile.empty() ? _certfile.c_str() : 0,
				     !_trusted_dir.empty() ? _trusted_dir.c_str() : 0))
    SSLSocket::err_ssl(0, "Couldn't read CA list", sa);

  SSL_CTX_set_verify_depth(_ctx, max_verify_depth + 1);
  SSL_CTX_set_verify(_ctx, _verify_mode,
		     _verify_callback ? _verify_callback : def_verify_cb);

  DEBUG2F("SSLContext::new_ctx(): %s", this->unparse().c_str());
  return _ctx;
}

void
SSLContext::free_ctx()
{
  if (_ctx) {
    SSL_CTX_free(_ctx);
    _ctx = NULL;
  }
}

std::string
SSLContext::get_ciphers() const
{
  if (!_ctx)
    return "";
  return unparse_ciphers(_ctx->cipher_list);
}

std::string
SSLContext::unparse() const
{
  std::ostringstream sa;
  sa << "CertFile: " << _certfile;
  if (!_keyfile.empty())
    sa << ", KeyFile: " << _keyfile;
  if (!_trusted_dir.empty())
    sa << ", TrustedDir: " << _trusted_dir;
  sa << ", IsClient: " << _is_client
     << ", EncryptionType: " << _enc_type
     << ", VerifyMode: " << _verify_mode;
  if (_verify_callback)
    sa << ", VerifyCallback: " << (_verify_callback ? "set" : "unset");
  if (_ctx)
    sa << ", Ciphers: " << get_ciphers();
  return sa.str();
}

std::string
SSLContext::unparse_ciphers(STACK_OF(SSL_CIPHER) *sk)
{
  if (!sk)
    return "";
  std::ostringstream sa;
  for (int i = 0; i < sk_SSL_CIPHER_num(sk); ++i) {
    SSL_CIPHER* c = sk_SSL_CIPHER_value(sk, i);
    if (!c) break;
    if (i != 0)
      sa << ":";
    sa << c->name;
  }
  return sa.str();
}

///////////////////////// class SSLSocket ////////////////////

void
SSLSocket::audit_ssl_connection(const InetSockAddrIn &/*address*/, std::string /*conn_msg*/,
                                std::string /*err_str*/, bool success)
{
  // Nada
}

void
SSLSocket::err_ssl(const std::string socket, const char *message, std::ostringstream &sa)
{
  std::string sslerr = get_ssl_err();
  if (!sslerr.empty()) {
    do {
      sa << sslerr << "\n";
      ERRORF("%s (%s): %s", message, socket.c_str(), sslerr.c_str());
      sslerr = get_ssl_err();
    } while (!sslerr.empty());
  } else {
    ERRORF("%s (%s)", message, socket.c_str());
  }
}

std::string
SSLSocket::get_ssl_err()
{
  unsigned errcode = ERR_get_error();
  if (errcode) {
    char buffer[256];
    ERR_error_string_n(errcode, buffer, sizeof buffer);
    return std::string(buffer);
  } else {
    return std::string();
  }
}

void
SSLSocket::err_ssl(const SSLSocket *s, const char *message, std::ostringstream &sa)
{
  if (s) {
    SSLSocket::err_ssl(socket_fd_peer(s->classname(), s->fd(), s->get_peer()), message, sa);
    return;
  }
  std::string sslerr = get_ssl_err();
  if (!sslerr.empty()) {
    do {
      sa << sslerr << "\n";
      ERRORF("%s: %s", message, sslerr.c_str());
      sslerr = get_ssl_err();
    } while (!sslerr.empty());
  } else ERRORF("%s", message);
}

void

SSLSocket::err_ssl(const std::string socket, const char *message, int err, std::ostringstream &sa)
{
  std::string sslerr = get_ssl_err();
  if (!sslerr.empty()) {
     do {
       sa << sslerr << "\n";
       ERRORF("%s (%s): %s", message, socket.c_str(), sslerr.c_str());
       sslerr = get_ssl_err();
    } while (!sslerr.empty());
  } else if (err == SSL_ERROR_NONE || err == SSL_ERROR_ZERO_RETURN) {
    // nothing to report
    DEBUGF("%s (%s): %d", message, socket.c_str(), err);
  } else if (errno != 0) {
    sa << "I/O error: " <<  strerror(errno);
    ERRORF("%s (%s): I/O error: %s", message, socket.c_str(),
	     strerror(errno));
  } else {
    sa << "(" << err << ")" << "EOF unexpected by SSL protocol";
    ERRORF("%s (%s): (%d) EOF unexpected by SSL protocol", message,
	   socket.c_str(), err);
  }
}

void
SSLSocket::err_ssl(const SSLSocket *s, const char *message, int err, std::ostringstream &sa)
{
  if (s) {
    SSLSocket::err_ssl(socket_fd_peer(s->classname(), s->fd(), s->get_peer()), message, err, sa);
    return;
  }
  unsigned errcode = ERR_get_error();
  if (errcode) {
    do {
      char buffer[256];
      ERR_error_string_n(errcode, buffer, sizeof buffer);
      sa << buffer << "\n";
      ERRORF("%s: %s", message, buffer);
    } while ((errcode = ERR_get_error()));
  } else if (err == SSL_ERROR_NONE || err == SSL_ERROR_ZERO_RETURN) {
    // nothing to report
    DEBUGF("%s: %d", message, err);
  } else if (errno != 0) {
    sa << "I/O error: " <<  strerror(errno);
    ERRORF("%s: I/O error: %s", message, strerror(errno));
  } else {
    sa << "(" << err << ")" << "EOF unexpected by SSL protocol";
    ERRORF("%s: (%d) EOF unexpected by SSL protocol", message, err);
  }
}

SSLSocket::SSLSocket(const SSLContext &context, SSL *ssl, int fd,
		     bool accepting, bool ssl_error, InetSockAddrIn *peer)
  : INETSocket(fd), _context(context), _ssl(ssl),
    _accepting(accepting), _ssl_error(ssl_error)
{
  if (peer) _peer=*peer;
  DEBUGF("SSLSocket::SSLSocket(%d, %p, %d)", _fd, (void *)&_ssl, (int)_accepting);
}

SSLSocket::~SSLSocket()
{
  close();
}

std::string
SSLSocket::get_session_ciphers(SSL *ssl)
{
  SSL_SESSION *sess = SSL_get_session(ssl);
  if (!sess)
    return "";
  return SSLContext::unparse_ciphers(sess->ciphers);
}

int
SSLSocket::connect(const InetSockAddrIn &address)
{
  AT_MOST_ONCE_A_SECOND
    (DEBUGF("SSLSocket::connect(%s), %i",
	   (address ? address.s().c_str() : _peer.s().c_str()), _conn_state));

  if (_conn_state == DISCONNECTED || _conn_state == IN_PROGRESS) {
    int r = inherited::connect(address);
    if (r != SOCK_OK)
      return r;
    if (_ssl)
      SSL_free(_ssl);
    SSLContext ctx(_context); // make sure it's only used once per connection
    _ssl = SSL_new(ctx.get_ctx());
    DEBUG2F("SSLSocket::connect(%s): %s",
	    (address ? address.s().c_str() : _peer.s().c_str()),
	    ctx.unparse().c_str());
    BIO *_sbio = BIO_new_socket(_fd, BIO_NOCLOSE);
    SSL_set_bio(_ssl, _sbio, _sbio);
    _conn_state = IN_PROGRESS_SSL;
  }

  int r = SSL_connect(_ssl);

  if (r <= 0) {
    int e = SSL_get_error(_ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
      return SOCK_AGAIN;
    // Audit failed SSL connection
    _ssl_error = true;
    std::ostringstream sa;
    err_ssl(this, "SSLSocket::connect: SSL connection error", e, sa);
    audit_ssl_connection(address ? address : get_peer(), "Establish Failed", sa.str(), false);
    _conn_state = DISCONNECTED;
    return SOCK_SSLERR;
  }

  if (SSL_get_verify_result(_ssl) != X509_V_OK) {
    // Audit failed SSL connection
    _ssl_error = true;
    std::ostringstream sa;
    err_ssl(this, "SSLSocket::connect: certificate does not verify", sa);
    audit_ssl_connection(address ? address : get_peer(), "Establish Failed", sa.str(), false);
    _conn_state = DISCONNECTED;
    return SOCK_SSLERR;
  }

  // Audit the established connection
  audit_ssl_connection(address ? address : get_peer(), "Established", "", true);
  INFOF("Established %s connection (%d->%s): %s",
	SSL_get_version(_ssl), _fd,
	(address ? address.s().c_str() : _peer.s().c_str()),
	get_cipher_info(_ssl).c_str());
  _conn_state = ESTABLISHED;
  return SOCK_OK;
}

void
SSLSocket::shutdown()
{
  int r;
  std::ostringstream sa;
  // Step 1: The underlying BIO is non-blocking.
  if ((r = SSL_shutdown(_ssl)) < 0) {
    int e = SSL_get_error(_ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
      r = SOCK_AGAIN;	// pretend to be success
    else {
      if (!(SSL_get_shutdown(_ssl) & SSL_RECEIVED_SHUTDOWN))
	err_ssl(this, "SSL shutdown send error", e, sa);
      r = SOCK_SSLERR;
    }
  } else if (r == 1) {	// peer has already closed
    r = SOCK_OK;
  } else if (r == 0)
    r = SOCK_AGAIN;
  else {	// unknown
    int e = SSL_get_error(_ssl, r);
    err_ssl(this, "SSL shutdown send error", e, sa);
    r = SOCK_SSLERR;
  }
  if (r != SOCK_AGAIN) {
    if (!_ssl_error) {
      if (r == SOCK_OK) // Audit successful ssl connection shutdown
	audit_ssl_connection(get_peer(), "Shutdown", "", true);
      else // Audit failure to shutdown ssl connection
	audit_ssl_connection(get_peer(), "Shutdown Failed", sa.str(), false);
    }
    _ssl_error = false;
    return;
  }

  // Step 2
  // should be poll() in loop, but we don't want to spend too much time here
  sleep(1);
  if ((r = SSL_shutdown(_ssl)) < 0) {
    int e = SSL_get_error(_ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
      ;	// we didn't wait long enough
    else if (e == SSL_ERROR_ZERO_RETURN)
      ; // done
    else if (!(SSL_get_shutdown(_ssl) & SSL_RECEIVED_SHUTDOWN)) {
      if (e != SSL_ERROR_SYSCALL || r != 0)
	err_ssl(this, "SSL shutdown recv error", e, sa);
    }
  } else if (r == 0)
    ;	// we just finished the step 1
  else if (r != 1) {	// unknown
    int e = SSL_get_error(_ssl, r);
    err_ssl(this, "SSL shutdown recv error", e, sa);
  }
  if (!_ssl_error) {
    if ((r == 0) || (r == 1)) // Audit successful ssl connection shutdown
      audit_ssl_connection(get_peer(), "Shutdown", "", true);
    else // Audit failure to shutdown ssl connection
      audit_ssl_connection(get_peer(), "Shutdown Failed", sa.str(), false);
  }
  _ssl_error = false;
}

int
SSLSocket::close()
{
  DEBUGF("SSLSocket::close(%d, %p)", _fd, (void*)&_ssl);
  if (_ssl) {
    shutdown();
    SSL_free(_ssl);
    _ssl = 0;
  }
  return inherited::close();
}

int
SSLSocket::accept(StreamSocket *&s, struct sockaddr *addr, socklen_t *addrlen)
{
  InetSockAddrIn peer;
  socklen_t peerlen = sizeof(peer);
  int new_fd = ::accept(_fd, (struct sockaddr *)&peer, &peerlen);
  std::ostringstream sa;
  if (new_fd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return SOCK_AGAIN;
    err_sys("SSLSocket::accept: accept() failed");
    return SOCK_ERR;
  }
  if (addr && addrlen && *addrlen > 0) {
    memcpy(addr, &peer, (peerlen > *addrlen) ? *addrlen : peerlen);
    *addrlen = peerlen;
  }

  if (fcntl(new_fd, F_SETFL, O_NONBLOCK) < 0) {
    err_sys("fcntl error");
    return SOCK_ERR;
  }

  BIO *new_bio = BIO_new_socket(new_fd, BIO_NOCLOSE);
  if (!new_bio) {
    // Audit failed ssl connection
    _ssl_error = true;
    err_ssl(socket_fd_peer(classname(),new_fd,peer), "SSLSocket:accept: BIO_new_socket() failed", sa);
    audit_ssl_connection(peer, "Establish Failed", sa.str(), false);
    ::close(new_fd);
    return SOCK_ERR;
  }

  SSLContext ctx(_context); // make sure it's only used once per connection
  SSL *new_ssl = SSL_new(ctx.get_ctx());
  DEBUG2F("SSLSocket::accept(%d<-%s): %s",
	  new_fd, peer.s().c_str(), ctx.unparse().c_str());
  if (!new_ssl) {
    // Audit failed ssl connection
    _ssl_error = true;
    err_ssl(socket_fd_peer(classname(),new_fd,peer), "SSLSocket:accept: SSL_new() failed", sa);
    audit_ssl_connection(peer, std::string("Establish Failed"), sa.str(), false);
    ::close(new_fd);
    return SOCK_ERR;
  }
  SSL_set_bio(new_ssl, new_bio, new_bio);

  int r = SSL_accept(new_ssl);
  if (r <= 0) {
    int e = SSL_get_error(new_ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
      INFOF("Established TCP connection (%d<-%s),"
	    " waiting for SSL handshake (%s)",
	    new_fd, peer.s().c_str(), get_cipher_info(new_ssl).c_str());
      s = new SSLSocket(_context, new_ssl, new_fd, true, false, &peer);
      return SOCK_OK;
    }
    if (HAS_NO_SHARED_CIPHER)
      ERRORF("SSLSocket::accept(%s): Session Ciphers: %s",
	     peer.s().c_str(), get_session_ciphers(new_ssl).c_str());
    // Audit failed ssl connection
    _ssl_error = true;
    err_ssl(socket_fd_peer(classname(),new_fd,peer), "SSLSocket::accept: failed", e, sa);
    audit_ssl_connection(peer, std::string("Establish Failed"), sa.str(), false);
    ::close(new_fd);
    SSL_free(new_ssl);
    return SOCK_SSLERR;
  }

  // Audit the established connection
  audit_ssl_connection(peer, std::string("Established"), "", true);
  INFOF("Established %s connection (%d<-%s): %s",
	SSL_get_version(new_ssl), new_fd,
	peer.s().c_str(), get_cipher_info(new_ssl).c_str());
  s = new SSLSocket(_context, new_ssl, new_fd, false, false, &peer);
  DEBUGF("SSLSocket::accept(%s): Session Ciphers: %s",
	 peer.s().c_str(), get_session_ciphers(new_ssl).c_str());
  return SOCK_OK;
}

int
SSLSocket::proceed()
{
  std::ostringstream sa;
  if (_accepting) {
    // The initial handshake is not complete.  Finish if possible.
    int r = SSL_accept(_ssl);
    if (r <= 0) {
      int e = SSL_get_error(_ssl, r);
      if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
	return SOCK_AGAIN;
      if (HAS_NO_SHARED_CIPHER)
	ERRORF("SSLSocket::proceed(%s): Session Ciphers: %s",
	       get_peer().s().c_str(), get_session_ciphers(_ssl).c_str());
      // Audit failed ssl connection
      _ssl_error = true;
      err_ssl(this, "SSLSocket::proceed() accept: failed", e, sa);
      audit_ssl_connection(get_peer(), std::string("Establish Failed"), sa.str(), false);
      // if (r == 0) // The underlying socket has likely been closed.
      // Set the SSL shutdown state accodingly to prevent the further read.
      SSL_set_shutdown(_ssl, SSL_get_shutdown(_ssl)|SSL_RECEIVED_SHUTDOWN);
      return SOCK_SSLERR;
    }
    // Audit the established connection
    audit_ssl_connection(get_peer(), std::string("Established"), "", true);
    INFOF("Established %s connection (%d<-%s): %s",
	  SSL_get_version(_ssl), _fd,
	  get_peer().s().c_str(), get_cipher_info(_ssl).c_str());
    _accepting = false;
    DEBUGF("SSLSocket::proceed(%s): Session Ciphers: %s",
	   get_peer().s().c_str(), get_session_ciphers(_ssl).c_str());
    return SOCK_OK;
  } else if (_conn_state == IN_PROGRESS || _conn_state == IN_PROGRESS_SSL) {
    return connect(InetSockAddrIn());
  } else if (_conn_state == DISCONNECTED) {
    // Audit failed ssl connection
    _ssl_error = true;
    audit_ssl_connection(get_peer(), std::string("Establish Failed"), "", false);
    return SOCK_SSLERR; // should not happen!
  } else {
    // A renegotiation handshake is in progress.  Finish if possible.
    char c[1];
    int r;
    if (SSL_want_read(_ssl)) {
      r = SSL_read(_ssl, c, 0);
      if (r < 0) {
	int e = SSL_get_error(_ssl, r);
	if (e == SSL_ERROR_ZERO_RETURN)
	  return SOCK_OK;
	if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
	  return SOCK_AGAIN;
	// Audit failed SSL read
	_ssl_error = true;
	err_ssl(this, "SSLSocket::proceed() read: failed", e, sa);
	audit_ssl_connection(get_peer(), std::string("Read Failed"), sa.str(), false);
	return SOCK_ERR;
      }
    } else if (SSL_want_write(_ssl)) {
      r = SSL_write(_ssl, c, 0);
      if (r < 0) {
	int e = SSL_get_error(_ssl, r);
	if (e == SSL_ERROR_ZERO_RETURN)
	  return SOCK_OK;
	if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
	  return SOCK_AGAIN;
	// Audit failed SSL write
	_ssl_error = true;
	err_ssl(this, "SSLSocket::proceed() write: failed", e, sa);
	audit_ssl_connection(get_peer(), std::string("Write Failed"), sa.str(), false);
	return SOCK_ERR;
      }
    }
    return SOCK_OK;
  }
}

std::string
SSLSocket::get_cipher_info(SSL *ssl)
{
  if (!ssl)
    return "No cipher information available";

  std::ostringstream sa;

  sa << "cipher name: ";
  const char *cipher_name = SSL_get_cipher_name(ssl);
  if (cipher_name)
    sa << cipher_name;
  else
    sa << "unknown";

  sa << " version: ";
  const char *version = SSL_get_cipher_version(ssl);
  if (version)
    sa << version;
  else
    sa << "unknown";

  int bits = SSL_get_cipher_bits(ssl, NULL);
  sa << " bits: " << bits;

  return sa.str();
}

int
SSLSocket::read(void *c, size_t len)
{
  if (_accepting || _conn_state == IN_PROGRESS_SSL) {
    int r = proceed();
    if (r != SOCK_OK)
      return r;
  }
  int r = SSL_read(_ssl, (char*)c, len);
  if (r <= 0) {
    int e = SSL_get_error(_ssl, r);
    if (e == SSL_ERROR_ZERO_RETURN)
      return SOCK_OK;
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
      return SOCK_AGAIN;
    // Audit failed SSL read
    _ssl_error = true;
    std::ostringstream sa;
    err_ssl(this, "SSLSocket::read: failed", e, sa);
    audit_ssl_connection(get_peer(), std::string("Read Failed"), sa.str(), false);
    if (r == 0)
      // The underlying socket has likely been closed.
      // Set the SSL shutdown state accodingly to prevent the further read.
      SSL_set_shutdown(_ssl, SSL_get_shutdown(_ssl)|SSL_RECEIVED_SHUTDOWN);
    else
      return SOCK_ERR;
  }
  return r;
}

int
SSLSocket::peek(void *c, size_t len)
{
  if (_accepting || _conn_state == IN_PROGRESS_SSL) {
    int r = proceed();
    if (r != SOCK_OK)
      return r;
  }
  int r = SSL_peek(_ssl, (char*)c, len);
  if (r <= 0) {
    int e = SSL_get_error(_ssl, r);
    if (e == SSL_ERROR_ZERO_RETURN)
      return SOCK_OK;
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
      return SOCK_AGAIN;
    // Audit failed SSL read
    _ssl_error = true;
    std::ostringstream sa;
    err_ssl(this, "SSLSocket::peek: failed", e, sa);
    audit_ssl_connection(get_peer(), std::string("Read Failed"), sa.str(), false);
    if (r == 0)
      // The underlying socket has likely been closed.
      // Set the SSL shutdown state accodingly to prevent the further read.
      SSL_set_shutdown(_ssl, SSL_get_shutdown(_ssl)|SSL_RECEIVED_SHUTDOWN);
    else
      return SOCK_ERR;
  }
  return r;
}

int
SSLSocket::write(const void *c, size_t len)
{
  if (_accepting || _conn_state == IN_PROGRESS
      || _conn_state == IN_PROGRESS_SSL) {
    int r = proceed();
    if (r != SOCK_OK)
      return r;
  }
#if 0
  if (len < 1)	// undefined behaviour: SSL_write() w/ zero
    return SOCK_OK;
#endif
  int r = SSL_write(_ssl, (const char*)c, len);
  if (r <= 0) {
    int e = SSL_get_error(_ssl, r);
    if (e == SSL_ERROR_ZERO_RETURN)
      return SOCK_OK;
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
      return SOCK_AGAIN;
    // Audit failed SSL write
    _ssl_error = true;
    std::ostringstream sa;
    err_ssl(this, "SSLSocket::write: failed", e, sa);
    audit_ssl_connection(get_peer(), std::string("Write Failed"), sa.str(), false);
    return SOCK_ERR;
  }
  return r;
}
