// -*- related-file-name: "../../include/mazu/mnmp/message.hh" -*-

#include "mnmp.hh"
#include "md5.hh"

// XXX: the read/write code really needs to be rewritten
static const int messagelenlen = sizeof(unsigned);
static const int messagetypelen = sizeof(MessageType);
static const int machineidlen = sizeof(NodeID);
static const int versionlen = sizeof(MNMP_VERSION);
static const int compressedflaglen = sizeof(unsigned);
static const unsigned MAX_MNMP_MESSAGE_LENGTH = 1<<22;

const std::string MNMPMessage::NULL_VERSION = "N/A";

bool MNMPMessage::_lz4_enabled = true;

uint32_t MNMPMessage::max_compressed_len( uint32_t in_len ) const
{
  // Return the maximum possible compressor output size,
  // regardless of which compressor is used.
  //
  // This account also for when the data is uncompressible
  // causing a compressor output to be larger than in_len.
  uint32_t max = in_len;

  uint32_t max_zlib = _zlib_compressor.out_len_max( in_len );
  if( max_zlib > max ) max = max_zlib;

  uint32_t max_lz4 = _lz4_compressor.out_len_max( in_len );
  if( max_lz4 > max ) max = max_lz4;

  return max;
}

static const char *mnmp_version_string(uint32_t v)
{
    switch (v)
    {
        case MNMP_VERSION: return "TP11";
        case MNMP_IR84_VERSION: return "IR84";
        case MNMP_FLOW82_VERSION: return "TP82";
        case MNMP_FLOW81_VERSION: return "TP81";
        case MNMP_FLOW72_VERSION: return "TPLG";
        default:
            static char vstr[5];
#define CHAR(c) (isprint((unsigned char) c) ? (c) : '*')
            sprintf (vstr, "%c%c%c%c", 
                     CHAR((v>>24) & 0xff), CHAR((v>>16) & 0xff),
                     CHAR((v>>8) & 0xff),  CHAR((v>>0) & 0xff));
            return vstr;
    }
}

MNMPMessage::MNMPMessage(MessageType m, NodeID src, NodeID dst)
  : _type(m), _src(src), _dst(dst), _compression(COMPRESSION_NONE),
    _uncompressed_len(0), _wirelen(0), _buf(0), _len(0), _pos(0), _hpos(0)
{
}

MNMPMessage::MNMPMessage(const MNMPMessage &m)
  : _type(m._type), _src(m._src), _dst(m._dst),
    _compression(m._compression), _uncompressed_len(m._uncompressed_len),
    _wirelen(m._wirelen), _buf(0), _len(0), _pos(0), _hpos(0)
{
  reserve_keys(m.n_tlvs());
  for (KeyMap::iterator j(&m._keys); j; j++)
    insert(j.value());
}

NodeType
MNMPMessage::src_type() const
{
  const TLV *t = find_key(NODE_TYPE_KEY);
  return t ? t->ulonglong_value() : 0;
}

std::string
MNMPMessage::src_sensor_type() const
{
  const TLV *t = find_key(SENSOR_TYPE_KEY);
  return t ? t->string_value() : "";
}

std::string
MNMPMessage::src_name() const
{
  const TLV *t = find_key(NAME_KEY);
  return t ? t->string_value() : "";
}

MNMPMessage &
MNMPMessage::operator=(const MNMPMessage &m)
{
  if (&m != this) {
    _type = m._type;
    _src = m._src;
    _dst = m._dst;
    _compression = m._compression;
    _uncompressed_len = m._uncompressed_len;
    _wirelen = m._wirelen;

    clear_keys();
    reserve_keys(m.n_tlvs());
    for (KeyMap::iterator j(&m._keys); j; j++)
      insert(j.value());
  }
  return *this;
}

int
MNMPMessage::read(StreamSocket &s)
{
  if (_hpos < sizeof(_header)) {
    static unsigned char pb[32];
    int pblen = 0;
    pblen = s.peek(pb, sizeof(pb));

    int r = s.read(((uint8_t *)&_header) + _hpos, sizeof(_header) - _hpos);
    if (r > 0) {
      _hpos += r;
      if (_hpos < sizeof(_header))
	return AGAIN;
    } else {
      switch (r) {
      case SOCK_AGAIN:  return AGAIN;
      case SOCK_SSLERR: return SSLERR;
      case SOCK_OK: return DONE;
      }
      return ERR;
    }

    if (_header.version != MNMP_VERSION
        && _header.version != MNMP_IR84_VERSION
	&& _header.version != MNMP_FLOW82_VERSION
        && _header.version != MNMP_FLOW81_VERSION
        && _header.version != MNMP_FLOW72_VERSION) { // still supported
      DEBUG3F("MNMPMessage::read(%d): peek (%d) %s",
	      s.fd(), pblen, ((pblen > 0) ? hex_s(pb, pblen).c_str() : ""));
      ERRORF("MNMPMessage::read(%d): bad MNMP version (received %x (%s), "
             "expected %x (%s), %x (%s), %x (%s), %x (%s), or %x (%s)", s.fd(),
	     _header.version, mnmp_version_string(_header.version),
             MNMP_VERSION, mnmp_version_string(MNMP_VERSION),
             MNMP_IR84_VERSION, mnmp_version_string(MNMP_IR84_VERSION),
             MNMP_FLOW82_VERSION, mnmp_version_string(MNMP_FLOW82_VERSION),
             MNMP_FLOW81_VERSION, mnmp_version_string(MNMP_FLOW81_VERSION),
             MNMP_FLOW72_VERSION, mnmp_version_string(MNMP_FLOW72_VERSION)
          );
      return ERR;
    }
    if (_header.length > MAX_MNMP_MESSAGE_LENGTH) {
      ERRORF("length %d exceeds limit (%d)", _header.length,
	     MAX_MNMP_MESSAGE_LENGTH);
      return ERR;
    }

    if (!(_buf = new uint8_t[_header.length])) {
      ERRORF("unable to allocate MNMPMessage read buffer of (%d) bytes", _header.length);
      return ERR;
    }

    _pos = 0;
  }

  int r = s.read(_buf + _pos, _header.length - _pos);
  if (r > 0) {
    _pos += r;
    if (_pos >= _header.length) {
      int r2 = make_from_char(_buf, _header.length);
      if (r2 < 0)
	ERRORF("MNMPMessage::read: make_from_char() failed");
      delete[] _buf; _buf = 0;
      _hpos = 0;
      return r2 < 0 ? ERR : DONE;
    }
    return AGAIN;
  } else if (!r)
    ERRORF("MNMPMessage::read: returned 0: connection closed by peer");

  switch (r) {
  case SOCK_AGAIN:  return AGAIN;
  case SOCK_SSLERR: return SSLERR;
  }
  return ERR;
}

#define READ32 char2unsigned(data); bytesleft-=4; data+=4;
#define READ64 char2ull(data); bytesleft-=8; data+=8;

int
MNMPMessage::make_from_char(const unsigned char *data, unsigned bytesleft)
{
  _wirelen = bytesleft;

  if (bytesleft < (messagetypelen + machineidlen * 2)) {
    ERRORF("bad MNMP message: not enough data");
    return -1;
  }

  DEBUG3F("MNMPMessage::make_from_char: bytesleft = %u", bytesleft);

  clear_keys();

  _type = (MessageType)READ32;
  _src = READ64;
  _dst = READ64;
  _compression = READ32;
  unsigned uncomp_keys_len = READ32;

  _uncompressed_len = messagetypelen + machineidlen*2 +
    compressedflaglen + messagelenlen + uncomp_keys_len;

  DEBUG3F("MNMPMessage::make_from_char: compression=%u and uncomp_keys_len=%u",
          _compression, uncomp_keys_len);

  if (bytesleft) {
    return (char2tlvs(data, bytesleft, uncomp_keys_len) < 0);
  }
  return 0;
}

int
MNMPMessage::write(StreamSocket &s)
{
  if (!_buf) {
    int buflen = versionlen + messagelenlen + max_serial_size();
    if (!(_buf = new uint8_t[buflen])) {
      ERRORF("unable to allocate MNMPMessage write buffer of (%d) bytes", buflen);
      return ERR;
    }
    // use any known non-default version id for this peer, if there is one
    const uint32_t &version = MNMP_VERSION;
    memcpy(_buf, &version, versionlen);
    _pos = 0;
    _len = versionlen + messagelenlen;
    int length = write(_buf + _len, buflen - _len);

    if (length < 0) {
      ERRORF("MNMPMessage::write: serialization error");
      delete[] _buf; _buf = 0;
      return ERR;
    } else {
      _len += length;
      unsigned2char(_buf + versionlen, length);
    }
  }

  int r = s.write(_buf + _pos, _len - _pos);
  if (r >= 0) {
    _pos += r;
    if (_pos >= _len) {
      delete[] _buf; _buf = 0;
      return DONE;
    }
    return AGAIN;
  }
  switch (r) {
  case SOCK_AGAIN:  return AGAIN;
  case SOCK_SSLERR: return SSLERR;
  }
  return ERR;
}

void
MNMPMessage::switch_source_dest()
{
  unsigned thing = _src;
  _src = _dst;
  _dst = thing;
}

std::string
MNMPMessage::type_string() const
{
  switch(_type) {
  case MN_UNDEFINED:              return "MN_UNDEFINED";
  case MN_HELLO:                  return "MN_HELLO";
  case MN_WELCOME:                return "MN_WELCOME";
  case MN_GOODBYE:                return "MN_GOODBYE";
  case MN_BEGINSLICE_MESSAGE:     return "MN_BEGINSLICE_MESSAGE";
  case MN_ENDSLICE_MESSAGE:       return "MN_ENDSLICE_MESSAGE";
  case MN_FLOWS_MESSAGE:          return "MN_FLOWS_MESSAGE";
  case MN_NETFLOW_FLOW_MESSAGE:   return "MN_NETFLOW_FLOW_MESSAGE";
  case MN_FLOW_MAPPINGS_MESSAGE:  return "MN_FLOW_MAPPINGS_MESSAGE";
  case MN_ANOMALY_MESSAGE:        return "MN_ANOMALY_MESSAGE";
  case MN_SERVER_PORT_MESSAGE:    return "MN_SERVER_PORT_MESSAGE";
  case MN_NTP_MESSAGE:            return "MN_NTP_MESSAGE";
  case MN_REMOTE_STATUS_MESSAGE:  return "MN_REMOTE_STATUS_MESSAGE";
  case MN_SIGNATURES_MESSAGE:     return "MN_SIGNATURES_MESSAGE";
  case MN_RBREQUEST_MESSAGE:      return "MN_RBREQUEST_MESSAGE";
  case MN_SOURCES_MESSAGE:        return "MN_SOURCES_MESSAGE";
  case MN_PACKETEER_MAPPINGS_MESSAGE:  return "MN_PACKETEER_MAPPINGS_MESSAGE";
  case MN_IFACE_RESOLVE_REQUEST_MESSAGE: return "MN_IFACE_RESOLVE_REQUEST_MESSAGE";
  case MN_IFACE_RESOLVE_RESPONSE_MESSAGE: return "MN_IFACE_RESOLVE_RESPONSE_MESSAGE";
  case MN_IFACE_REST_RESOLVE_REQUEST_MESSAGE: return "MN_IFACE_REST_RESOLVE_REQUEST_MESSAGE";  
  case MN_SSH_KEY_EXCHANGE_MESSAGE: return "MN_SSH_KEY_EXCHANGE_MESSAGE";
  case MN_TARARI_STATUS_MESSAGE:  return "MN_TARARI_STATUS_MESSAGE";
  case MN_NBAR_MAPPINGS_MESSAGE:  return "MN_NBAR_MAPPINGS_MESSAGE";
  case MN_SILENTHOSTS_MESSAGE:	  return "MN_SILENTHOSTS_MESSAGE";
  case MN_CONTROL_MESSAGE:	  return "MN_CONTROL_MESSAGE";
  case MN_NODE_RESOLVE_REQUEST_MESSAGE: return "MN_NODE_RESOLVE_REQUEST_MESSAGE";
  case MN_NODE_RESOLVE_RESPONSE_MESSAGE: return "MN_NODE_RESOLVE_RESPONSE_MESSAGE";
  case MN_NODE_REST_RESOLVE_REQUEST_MESSAGE: return "MN_NODE_REST_RESOLVE_REQUEST_MESSAGE";
  case MN_ANOMALY_DONE_MESSAGE:        return "MN_ANOMALY_DONE_MESSAGE";
  case MN_FLOW_LOGGING_DONE_MESSAGE:   return "MN_FLOW_LOGGING_DONE_MESSAGE";
  case MN_REFRESH_DNSNAMES_MESSAGE:    return "MN_REFRESH_DNSNAMES_MESSAGE";
  case MN_RESOLVED_IP_TO_DNS_MESSAGE:  return "MN_RESOLVED_IP_TO_DNS_MESSAGE";
  case MN_CLEAR_DNS_DEVICE_CACHE:      return "MN_CLEAR_DNS_DEVICE_CACHE";
  case MN_REST_NODES_MESSAGE:      return "MN_REST_NODES_MESSAGE";
  case MN_REST_NODES_PRIORITY_REFRESH_REQUEST_MESSAGE: return "MN_REST_NODES_PRIORITY_REFRESH_REQUEST_MESSAGE";
  case MN_REST_NODES_PRIORITY_REFRESH_RESPONSE_MESSAGE: return "MN_REST_NODES_PRIORITY_REFRESH_RESPONSE_MESSAGE";
  case MN_SENSOR_CONNECTIONS_MESSAGE:     return "MN_SENSOR_CONNECTIONS_MESSAGE";
  case MN_RESET_SENSOR_CONNECTIONS_MESSAGE:     return "MN_RESET_SENSOR_CONNECTIONS_MESSAGE";
  case MN_FLOW_LIMIT_STATS_MESSAGE:  return "MN_FLOW_LIMIT_STATS_MESSAGE";
  case MN_APP_MAPPINGS_MESSAGE:   return "MN_APP_MAPPINGS_MESSAGE";
  case MN_ONE_MIN_ROLLUP_LOGGING_DONE_MESSAGE: return "MN_ONE_MIN_ROLLUP_LOGGING_DONE_MESSAGE";
  case MN_FLOWS_TO_AGGREGATE_MESSAGE: return "MN_FLOWS_TO_AGGREGATE_MESSAGE";
  case MN_REPORTED_PEER_INFO_MESSAGE: return "MN_REPORTED_PEER_INFO_MESSAGE";
  case MN_TRACKED_INTERFACES_MESSAGE: return "MN_TRACKED_INTERFACES_MESSAGE";
  case MN_ALLOY_OAUTH_MESSAGE: return "MN_ALLOY_OAUTH_MESSAGE";
  case MN_MGMT_TIME_STATUS_MESSAGE: return "MN_MGMT_TIME_STATUS_MESSAGE";
  }
  std::ostringstream sa;
  sa << "<MESSAGE UNKNOWN (" << int(_type) << ")>";

  return sa.str();
}


std::string
MNMPMessage::s() const
{
  std::ostringstream sa;

  sa << type_string();
  sa << " source " << _src << ", dest " << _dst;
  sa << ", compression " << _compression;
  sa << ", uncompressed len " << _uncompressed_len;
  sa << ", wire len " << _wirelen << "\n";
  sa << _keys.s();
  return sa.str();
}

#define WRITE32(WHAT) unsigned2char(buf+pos, WHAT); pos+=4;
#define WRITE64(WHAT) ull2char(buf+pos, WHAT); pos+=8;

int
MNMPMessage::write(unsigned char *buf, int buflen) const
{
  int pos = 0;

  if (buflen - pos < messagetypelen + 2*machineidlen)
    return -1;

  WRITE32(unsigned(_type));
  WRITE64(_src);
  WRITE64(_dst);

  uint32_t selected_compression = compression_selection();
  WRITE32( selected_compression );

  unsigned keys_len = _keys.serial_size();
  WRITE32( keys_len );

  switch( selected_compression )
  {
  case COMPRESSION_NONE: {
      pos += _keys.write(buf + pos, buflen - pos, 0);
    }
    break;
  case COMPRESSION_ZLIB: {
       pos = write_compressed( _zlib_compressor, keys_len, buf, buflen, pos );
    }
    break;
  case COMPRESSION_LZ4: {
       pos = write_compressed( _lz4_compressor, keys_len, buf, buflen, pos );
    }
    break;
  default:
    ERRORF("Compression format not implemented (%i,%i)", _compression, selected_compression  );
    pos = -1;
  }

  return pos;
}

MNMPMessage::CompressionType
MNMPMessage::compression_selection( ) const
{
  // Determine effective compression to use depending on:
  //   - Preferred compression algo indicated by _compression.
  //   - configuration override (e.g. _lz4_enabled).
  //   - Compression supported by receiver (peer node).

  if( _compression == COMPRESSION_NONE ) return COMPRESSION_NONE;
 
  if( _compression == COMPRESSION_LZ4 )
  {
    // Check configuration overrides
    if( MNMPMessage::_lz4_enabled == false ) {

      return COMPRESSION_ZLIB;
    }

    // Force ZLIB with older MNMP version.
    uint32_t peer_version = MNMP_VERSION;
    switch( peer_version )
    {
    case MNMP_IR84_VERSION:
    case MNMP_FLOW82_VERSION:
    case MNMP_FLOW81_VERSION:
    case MNMP_FLOW72_VERSION:
      return COMPRESSION_ZLIB;
    }
  }

  return _compression; // Use preferred compression algo.
}


int
MNMPMessage::write_compressed( const BlockCompressor &compressor, int in_len, unsigned char *buf, int buflen, int pos) const
{
  unsigned char *in = new unsigned char[in_len];
  _keys.write(in, in_len, 0);
  int32_t out_len_max = compressor.out_len_max( in_len );
  unsigned char *out = new unsigned char[out_len_max];

  int32_t out_len = compressor.compress( in, in_len, out );

  if( out_len > 0 ) {
    if(out_len <= buflen - pos) {
      // TODO: Write directly in 'buf' and remove 'out' alloc+memcpy.
      memcpy(buf + pos, out, out_len);
      pos += out_len;
    } else {
      ERRORF("Would-be buffer overrun in MNMPMessage::write");
      pos = -1;
    }
  } else {
    ERRORF("Failed to compress a message");
    pos = -1;
  }

  delete[] out;
  delete[] in;

  return pos;
}

int
MNMPMessage::char2tlvs(const unsigned char *buf,
		       int buflen, unsigned uncomp_keys_len)
{
  if(_compression == COMPRESSION_NONE)
    return _keys.read(buf, buflen);

  uint8_t *uncomp_keys = new uint8_t[uncomp_keys_len];
  unsigned long real_uncomp_len = uncomp_keys_len;
  switch( _compression )
  {
  case COMPRESSION_LZ4:
    {
      real_uncomp_len = _lz4_compressor.decompress( buf, buflen, 
                                                    uncomp_keys, 
                                                    uncomp_keys_len );
    }
    break;
  case COMPRESSION_ZLIB:
    {
      real_uncomp_len = _zlib_compressor.decompress( buf, buflen,
                                                     uncomp_keys,
                                                     uncomp_keys_len );

    }
    break;
  default:
    delete[] uncomp_keys;
    ERRORF("Unsupported compression type (%i)", _compression );
    return -1;
  }

  if( real_uncomp_len <= 0 ) {
    delete[] uncomp_keys;
    ERRORF("Failed to uncompress a message");
    return -1;
  }

  int r = _keys.read(uncomp_keys, real_uncomp_len);
  delete[] uncomp_keys;
  return r;
}

int
MNMPMessage::max_serial_size() const
{
  int len = messagetypelen + machineidlen * 2;
  int keys_serial_size = _keys.serial_size();
  return len + max_compressed_len(keys_serial_size);
}

//////////////////// Authentication utility methods //////////////////////////

// adds a default challenge TLV and returns it
Challenge
MNMPMessage::add_challenge()
{
  Challenge challenge;
  time(&challenge.t);
  challenge.r = random();
  TLV ct(CHALLENGE_KEY);
  ct.set_value((unsigned char *)&challenge, sizeof(Challenge));
  insert(ct);
  return challenge;
}

// adds a MD5_AUTH_KEY TLV for the password+challenge
void
MNMPMessage::add_auth(const char *password, MNMPMessage *challenge_message)
{
  MazuMD5 encoder;
  const TLV* challenge_tlv = challenge_message->find_key(CHALLENGE_KEY);
  const unsigned char* challenge = challenge_tlv? challenge_tlv->value() : NULL;
  int challenge_length =  challenge_tlv? challenge_tlv->length() : 0;
  unsigned len = strlen(password) + challenge_length;
  unsigned char buffer [1024];

  memcpy (buffer, password, strlen(password));
  memcpy (buffer+strlen(password), challenge, challenge_length);

  encoder.update (buffer, len);
  encoder.finalize();

  unsigned char *digest = encoder.raw_digest();
  TLV auth(MD5_AUTH_KEY);
  auth.set_value(digest, MD5_DIGEST_LENGTH);
  delete[] digest;

  insert(auth);
}

// check if MD5_AUTH_KEY TLV is present and is indeed for the password
bool
MNMPMessage::check_auth(const char *password, Challenge challenge)
{
  int challenge_length = sizeof(Challenge);

  const TLV *theirs = find_key(MD5_AUTH_KEY);
  if (!theirs)
    return false;

  bool result = false;
  MazuMD5 encoder;

  unsigned len = strlen(password) + challenge_length;
  unsigned char buffer[1024];
  memcpy(buffer, password, strlen(password));
  memcpy(buffer + strlen(password), &challenge, challenge_length);

  encoder.update((const unsigned char *)buffer, len);
  encoder.finalize();

  unsigned char *digest = encoder.raw_digest();
  result = (theirs->length() == MD5_DIGEST_LENGTH)
    && (memcmp(theirs->value(), digest, MD5_DIGEST_LENGTH) == 0);

  delete[] digest;
  return result;
}

std::string
MNMPMessage::version_s(const uint32_t &version, const SourceNodeType::nodetype_t &type)
{
  std::ostringstream sa;
  if (SourceNodeType::is_alloy(type))
    sa << "A";
  else if (SourceNodeType::is_shark(type))
    sa << "S";
  else
    sa << "M";
 
  switch (version) {
  case MNMP_VERSION: sa << "11.0"; break;
  case MNMP_IR84_VERSION: sa << "8.4"; break;
  case MNMP_FLOW82_VERSION: sa << "8.2"; break;
  case MNMP_FLOW81_VERSION: sa << "8.1"; break;
  case MNMP_FLOW72_VERSION: sa << "7.2"; break;
  default: sa.clear(); sa << NULL_VERSION; break;
  }
  return sa.str();
}

HelloMessage::HelloMessage(NodeID from, NodeID to, NodeType type,
			   const std::string &name, const std::string &sensor_type)
  : MNMPMessage(MN_HELLO, from, to)
{
  TLV node_type(NODE_TYPE_KEY);
  node_type.set_value(type);
  insert(node_type);
  if (!name.empty())
    insert(TLV(NAME_KEY, name.c_str()));
  if (!sensor_type.empty()) {
    insert(TLV(SENSOR_TYPE_KEY, sensor_type.c_str()));
    // Send the REST port only for shark express, for now.
    // It ends up in the peer_info DB table used for click-to-packet.
    if (sensor_type == "sharkexpress") {
      insert(TLV(MGMT_PORT_KEY, 443));
      insert(TLV(CONTROL_PORT_KEY, 443));
    }
  }
}

WelcomeMessage::WelcomeMessage(NodeID from, NodeID to, NodeType type,
			       const std::string &name, const std::string &sensor_type)
  : MNMPMessage(MN_WELCOME, from, to)
{
  // identical to MN_HELLO, for now
  TLV node_type(NODE_TYPE_KEY);
  node_type.set_value(type);
  insert(node_type);
  if (!name.empty())
    insert(TLV(NAME_KEY, name.c_str()));
  if (!sensor_type.empty())
    insert(TLV(SENSOR_TYPE_KEY, sensor_type.c_str()));
}

GoodbyeMessage::GoodbyeMessage(NodeID from)
  : MNMPMessage(MN_GOODBYE, from, NODE_ALL)
{
}

std::string
hex_s(const void *b, size_t len)
{
  char chars[] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
  };
  const unsigned char *buf = static_cast<const unsigned char *>(b);
  std::ostringstream sa;
  for(unsigned i = 0; i < len; i++) {
    if (sa)
      sa << " ";
    char c = buf[i];
    sa << chars[(c & 0xF0) >> 4] << chars[c & 0x0F];
  }
  return sa.str();
}

NetflowFlowsMessage::NetflowFlowsMessage(NodeID src, NodeID dst)
  : MNMPMessage(MN_NETFLOW_FLOW_MESSAGE, src, dst)
{
}

void
NetflowFlowsMessage::add(const unsigned char *p, size_t len)
{
  TLV &t(_keys.alloc_key(NETFLOW_RAW_FLOW_KEY));
  unsigned char *buffer = t.alloc_value(len);
  if (buffer) {
    memcpy(buffer, p, len);
  }
  else {
    AT_MOST_ONCE_A_MINUTE(ERRORF("failed to allocate buffer in NetflowFlowsMessage"));
  }
}
