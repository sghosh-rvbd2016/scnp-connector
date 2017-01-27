
#include "tlv.hh"
#include "socket.hh"
#include "logging.hh"

TLV TLV::the_null_tlv;

TLV::TLV()
  : _key(UNDEFINED_KEY), _length(0), _value(0)
{
}

TLV::TLV(Key k)
  : _key(k), _length(0), _value(0)
{
}

TLV::TLV (Key k, const char *value)
  : _key(k), _length(0), _value(0)
{
  if (value)
    set_value((const unsigned char *)value, strlen(value) + 1);
}

TLV::TLV(const TLV &t)
  : _key(t._key)
{
  if (t._value) {
    if ((_value = new unsigned char[t._length])) {
      _length = t._length;
      memcpy(_value, t._value, _length);
    } else {
      _length = 0;
      ERRORF("out of memory");
    }
  } else {
    _value = 0;
    _length = 0;
  }
}

TLV &TLV::operator=(const TLV &t)
{
  if (&t != this) {		// self assignment
    _key = t._key;
    delete[] _value;
    if (t._value) {
      if ((_value = new unsigned char[t._length])) {
        _length = t._length;
        memcpy(_value, t._value, _length);
      } else {
        _length = 0;
        ERRORF("out of memory");
      }
    } else {
      _value = 0;
      _length = 0;
    }
  }
  return *this;
}

int
TLV::read(const unsigned char *buf, int buflen)
{
  delete[] _value;
  _value = 0;
  _length = 0;

  if (buflen < keylen + lenlen) {
    WARNINGF("incomplete tag-length-value triplet at end of message");
    return -1;
  }

  _key = (Key)char2unsigned(buf);
  int new_length = char2unsigned(buf + keylen);

  if (buflen < keylen + lenlen + new_length) {
    WARNINGF("incomplete tag-length-value triplet at end of message");
    return -1;
  } else if (!(_value = new unsigned char[new_length])) {
    ERRORF("out of memory");
    return -1;
  } else {
    _length = new_length;
    memcpy(_value, buf + keylen + lenlen, new_length);
    return keylen + lenlen + new_length;
  }
}

// returns -1 if not enough space in 'buf'; otherwise, # of characters written
int
TLV::write(unsigned char *buf, int buflen) const
{
  if (buf == 0)
    buflen = 0;
  if (keylen + lenlen + _length > buflen) {
    return -1;
  } else {
    unsigned2char(buf, _key);
    unsigned2char(buf + keylen, _length);
    memcpy(buf + keylen + lenlen, _value, _length);
    return keylen + lenlen + _length;
  }
}

void
TLV::set_value(const unsigned char *c, unsigned l)
{  
  delete[] _value;
  _length = _align(l);
  _value = new unsigned char[_length];
  if (_value) {
    memcpy(_value, c, l);
    _pad(_value, l);
  } else {
    ERRORF("out of memory");
    _length = 0;
  }
}

unsigned char *
TLV::alloc_value(unsigned l)
{
  delete [] _value;
  _length = _align(l);
  _value = new unsigned char[_length];
  if (_value) {
    _pad(_value, l);
  } else {
    ERRORF("out of memory");
    _length = 0;
  }
  return _value;
}

// 4-byte align
int
TLV::_align(int l)
{
  int rem = l % 4;
  return l + (rem ? (4 - rem) : 0);
}

// pad with zeros
void
TLV::_pad(unsigned char *c, int l)
{
  int rem = l % 4;
  if (rem)
    for (int i = 0; i < (4 - rem); i++)
      c[l + i] = 0;
}

std::string
TLV::string_value() const
{
  int len = _length;		// trim trailing '\0's
  while (len > 0 && _value[len - 1] == '\0')
    len--;
  return std::string(reinterpret_cast<const char *>(_value), len);
}

std::string
TLV::s() const
{
  std::ostringstream sa;
  switch (_key) {
  case ANALYZER_NUMBER:       sa << "analyzer number: "; break;
  case ANOMALY_KEY:           sa << "anomaly : "; break;
  case ANOMALY_TYPE_KEY:      sa << "anomaly type: "; break;
  case AUTH_CHALLENGE_KEY:    sa << "auth challenge: "; break;
  case CONTROL_PORT_KEY:      sa << "control port: "; break;
  case AUTH_MODE_KEY:         sa << "auth mode key: "; break;
  case AUTH_PROTO_KEY:        sa << "auth protocol key: "; break;
  case AUTH_PSSWD_KEY:        sa << "auth password key: "; break;
  case CHALLENGE_KEY:         sa << "challenge: "; break;
  case CTXT_NAME_KEY:         sa << "context name key: "; break;
  case DNSRESOLVE_KEY:        sa << "dns resolve key: "; break;
  case FLOW_SENSOR100:        sa << "flows(Sensor 8.4-10.0* format): "; break;
  case FLOW_INTELRG:          sa << "flows(Intel RG): "; break;
  case FLOW_SENSOR108:        sa << "flows(Sensor 10.5-10.8*): "; break;
  case FLOW:                  sa << "flows: "; break;
  case FLOW72:                sa << "flows(7.2 format): "; break;
  case FLOW81:                sa << "flows(8.1 format): "; break;
  case FLOW83:                sa << "flows(8.3 format): "; break;
  case FLOW_RG83:             sa << "flows(RG 8.3 format): "; break;
  case FLOW96:                sa << "flows(8.4-9.6 format): "; break;
  case FLOW100:               sa << "flows(10.0* format): "; break;
  case FLOW105:               sa << "flows(10.5* format): "; break;
  case FLOW106:               sa << "flows(10.6 format): "; break;
  case FLOW107:               sa << "flows(10.7 format): "; break;
  case FLOW108:               sa << "flows(10.8 format): "; break;
  case FLOWMAPPING_KEY:       sa << "flow mapping: "; break;
  case FLOWMAPPING_TYPE_KEY:  sa << "flow mapping type: "; break;
  case FLOW_LOG:              sa << "flow log: "; break;
  case IPADDRESS_KEY:         sa << "address: "; break;
  case MD5_AUTH_KEY:          sa << "md5 auth: "; break;
  case MGMT_PORT_KEY:         sa << "management port: "; break;
  case MNMP_CONNECTION_STATUS_KEY:         sa << "mnmp connection status: "; break;
  case REMOTE_STATUS_KEY:     sa << "remote status: "; break;
  case NAME_KEY:              sa << "name: "; break;
  case NETFLOW_FLOW_KEY:      sa << "netflow flow type: "; break;
  case NODE_TYPE_KEY:         sa << "node type: "; break;
  case IS_VIRTUAL_KEY:        sa << "is virtual src: "; break;
  case NTP_STATUS:            sa << "ntp status: "; break;
  case PRIV_MODE_KEY:         sa << "priv mode key: "; break;
  case PRIV_PROTO_KEY:        sa << "priv proto key: "; break;
  case PRIV_PSSWD_KEY:        sa << "priv password key: "; break;
  case PROTOCOLS:             sa << "custom protocols: "; break;
  case SENSOR_TYPE_KEY:       sa << "sensor type: "; break;
  case SERVER_LIKELIHOOD_KEY: sa << "server likelihood key: "; break;
  case SLICE_ENDED_KEY:       sa << "slice ended: "; break;
  case SLICE_LENGTH_KEY:      sa << "slice length: "; break;
  case IFACE_KEY: 	      sa << "interface key: "; break;
  case IFALIAS_KEY:           sa << "ifalias key: "; break;
  case COMMUNITY_KEY:         sa << "community key: "; break;
  case IFDESCR_KEY:           sa << "iface descr key: "; break;
  case IFTYPE_KEY:            sa << "iface type key: "; break;
  case IFMTU_KEY:             sa << "iface mtu key: "; break;
  case IFSPEED_KEY:           sa << "iface speed key: "; break;
  case IFMAC_KEY:             sa << "iface MAC key: "; break;
  case IFACE_HIPRIORITY_KEY:  sa << "iface high priority key: "; break;
  case IP_KEY:                sa << "IP address key: "; break;
  case IPX_KEY:               sa << "IPx address key: "; break;
  case PEER_VENDOR_KEY:       sa << "peer vendor key: "; break;
  case PEER_MODEL_KEY:        sa << "peer model key: "; break;
  case PEER_VERSION_KEY:      sa << "peer version key: "; break;
  case PROXY_SERVER_KEY:      sa << "proxy server key: "; break;
  case SEC_LEVEL_KEY:         sa << "security level key: "; break;
  case SEC_NAME_KEY:          sa << "security name key: "; break;
  case SENSOR_CONNECTIONS_KEY:  sa << "sensor connections key: "; break;
  case RESET_SENSOR_CONNECTIONS_KEY:  sa << "reset sensor connections key: "; break;
  case REMOTE_NODE_TYPE_KEY:  sa << "remote node type: "; break;
  case REMOTE_SENSOR_TYPE_KEY:  sa << "remote sensor type: "; break;
  case SYSNAME_KEY:           sa << "system name key: "; break;
  case SNMP_VERSION_KEY:      sa << "SNMP version key:"; break;
  case SLICEFLOWS_KEY:        sa << "slice flows: "; break;
  case TARS_INITIALIZED_KEY:  sa << "tarari initialized key: "; break;
  case TARS_SUBMITTED_KEY:    sa << "tarari jobs submitted key: "; break;
  case TARS_BYTES_KEY:        sa << "tarari bytes processed key: "; break;
  case TARS_ERRORS_KEY:       sa << "tarari errors key: "; break;
  case TARS_ACTIVE_KEY:       sa << "tarari jobs active key: "; break;
  case TARS_SKIPPED_KEY:      sa << "tarari jobs skipped ker: "; break;
  case BGP_AS_KEY:            sa << "bgp as key : "; break;
  case DISPATCHER_FLOW_LIMIT: sa << "dispatcher flow_limit : "; break;
  case DISPATCHER_N_FLOWS:    sa << "dispatcher flow_received: "; break;
  case DISPATCHER_OVERFLOW_LIMIT:
                              sa << "dispatcher overflow_limit : "; break;
  case DISPATCHER_N_OVERFLOWS:
                              sa << "dispatcher overflowed: "; break;
  case APP_MAPPING_KEY:       sa << "app mapping key : "; break;
  case RAWFLOWTOAGGREGATE_KEY:
                              sa << "raw flow to aggregate: "; break;
  case TRACKED_INTERFACES_KEY:
                              sa << "tracked interfaces: "; break;
  case RAWFLOWCOUNT_KEY:      sa << "raw flow count: "; break;
  case RAWFLOWRESULT_KEY:     sa << "raw flow result: "; break;
  case RESTNODEOP_KEY:        sa << "REST node operation key: "; break;
  case CBQOS_CONFIG_KEY:      sa << "CB QoS config key: "; break;
  case CBQOS_STATS_KEY:       sa << "CB QoS stats key: "; break;
  case OAUTH_KEY:             sa << "Oauth key: "; break;
  case MGMT_TIME_STATUS:      sa << "MGMT Time Status: "; break;  
  case UNDEFINED_KEY:         sa << "undefined key: "; break;
  default:                    sa << "unknown key (" << (int)_key <<  "): ";
  }

  // output values in formats that make sense for the key
  switch (_key) {
  case NAME_KEY:
  case SENSOR_TYPE_KEY:
  case COMMUNITY_KEY:
  case IFALIAS_KEY:
  case IFDESCR_KEY:
  case SYSNAME_KEY:
  case PEER_VENDOR_KEY:
  case PEER_MODEL_KEY:
  case PEER_VERSION_KEY:
  case PROXY_SERVER_KEY:
  case SEC_NAME_KEY:
  case SENSOR_CONNECTIONS_KEY:
  case RESET_SENSOR_CONNECTIONS_KEY:
  case AUTH_PSSWD_KEY:
  case PRIV_PSSWD_KEY:
  case CTXT_NAME_KEY:
  case CBQOS_CONFIG_KEY:
  case CBQOS_STATS_KEY:
  case REMOTE_SENSOR_TYPE_KEY:
  case MNMP_CONNECTION_STATUS_KEY:
  case REMOTE_STATUS_KEY:
  case OAUTH_KEY:
    sa << string_value();
    break;
  case MGMT_TIME_STATUS:
    sa << string_value();
    break;
  case NODE_TYPE_KEY:
  case REMOTE_NODE_TYPE_KEY:
  case RAWFLOWCOUNT_KEY:
    sa << ulonglong_value();
    break;
  case SLICE_ENDED_KEY:
  case SLICE_LENGTH_KEY:
  case FLOWMAPPING_TYPE_KEY:
  case ANOMALY_TYPE_KEY:
  case ANALYZER_NUMBER:
  case IFTYPE_KEY:
  case IFMTU_KEY:
  case IFSPEED_KEY:
  case SNMP_VERSION_KEY:
  case MGMT_PORT_KEY:
  case CONTROL_PORT_KEY:
  case SEC_LEVEL_KEY:
  case AUTH_MODE_KEY:
  case AUTH_PROTO_KEY:
  case PRIV_MODE_KEY:
  case PRIV_PROTO_KEY:
  case BGP_AS_KEY:
  case DISPATCHER_FLOW_LIMIT:
  case DISPATCHER_OVERFLOW_LIMIT:
  case DISPATCHER_N_FLOWS:
  case DISPATCHER_N_OVERFLOWS:
  case RAWFLOWRESULT_KEY:
    sa << unsigned_value();
    break;
  case IFACE_HIPRIORITY_KEY:
  case IS_VIRTUAL_KEY:
    sa << bool_value();
    break;
  case NTP_STATUS:
    {
      NTPStatus s;
      get_value(s);
      sa << s;
    }
    break;
  default:
    sa << _length << ": ";
    char c[3];
    for (int i = 0; i < _length; i++) {
      sprintf(c, "%02X", _value[i]);
      sa << c;
    }
  }

  return sa.str();
}

int
KeyMap::read(const unsigned char *buf, int buflen)
{
  int pos = 0;
  while (pos < buflen) {
    TLV &tlv(alloc_key(0));
    int bytesread = tlv.read(buf + pos, buflen - pos);
    if (bytesread < 0)
    {
      _tlvs.pop_back();
      return -1;
    }
    pos += bytesread;
  }
  return pos;
}

const TLV &
KeyMap::operator[](Key k) const
{
  for (unsigned i = 0; i < _tlvs.size(); i++)
    if (_tlvs[i].key() == k)
      return _tlvs[i];
  return TLV::null_tlv();
}

int
KeyMap::get_multiple(Key k, std::vector<TLV> &tlvs) const
{
  int in_size = tlvs.size();
  for (unsigned i = 0; i < _tlvs.size(); i++)
    if (_tlvs[i].key() == k)
      tlvs.push_back(_tlvs[i]);
  return tlvs.size() - in_size;
}

const TLV *
KeyMap::findp(Key k) const
{
  for (unsigned i = 0; i < _tlvs.size(); i++)
    if (_tlvs[i].key() == k)
      return &_tlvs[i];
  return 0;
}

TLV *
KeyMap::findp(Key k)
{
  for (unsigned i = 0; i < _tlvs.size(); i++)
    if (_tlvs[i].key() == k)
      return &_tlvs[i];
  return 0;
}

int
KeyMap::write(unsigned char *buf, int buflen, const Key *ignore) const
{
  int pos = 0;
  for (KeyMap::iterator i(this); i; i++) {
    const TLV &t = i.value();
    int t_len;
    if (ignore)
      for (int i = 0; ignore[i]; i++)
	if (ignore[i] == t.key())
	  goto ignore_t;
    t_len = t.write(buf + pos, buflen - pos);
    if (t_len < 0)
      return -1;
    pos += t_len;
   ignore_t: ;
  }
  return pos;
}

std::string
KeyMap::s() const
{
  std::ostringstream sa;
  for (KeyMap::iterator i(this); i; i++)
    sa << "  " << i.value().s() << "\n";
  return sa.str();
}
