#pragma once

#include <string>
#include <vector>
#include <stdint.h>
#include <stdio.h>
#include "socket.hh"

enum {
  UNDEFINED_KEY = 0,
  NAME_KEY = 16,
  NODE_TYPE_KEY = 130,		// sensor, dispatcher, etc
  IS_VIRTUAL_KEY = 131,
  IPADDRESS_KEY = 134,
  MD5_AUTH_KEY = 143,
  CHALLENGE_KEY = 144,
  AUTH_CHALLENGE_KEY = 145,
  SENSOR_TYPE_KEY = 147,	// Mazu, other, etc

  SLICE_ENDED_KEY = 240,
  SLICE_LENGTH_KEY = 241,
  PROTOCOLS = 242,

  FLOW_SENSOR100 = 243,
  FLOW72 = 244,
  FLOW_LOG = 245,
  FLOW81 = 246,
  FLOW83 = 247,
  FLOW_RG83 = 248,
  FLOW96 = 249,

  TIME_START_KEY = 250,
  TIME_END_KEY = 251,
  TCP_NPORTS_KEY = 252,
  TCP_PORT_KEY = 253,
  TCP_PORT_BYTE_KEY = 254,
  UDP_NPORTS_KEY = 255,
  UDP_PORT_KEY = 256,
  UDP_PORT_BYTE_KEY = 257,

  FLOWMAPPING_KEY = 260,
  FLOWMAPPING_TYPE_KEY = 261,
  TYPED_FLOWMAPPING_KEY = 262,

  ANOMALY_KEY = 270,
  ANOMALY_TYPE_KEY = 271,

  SERVER_LIKELIHOOD_KEY = 272,
  PORT_HISTOGRAM_KEY = 273,

  ANALYZER_NUMBER = 280,
  NTP_STATUS = 281, // binary struct NTPStatus

  SSH_KEY_EXCHANGE_KEY = 290,

  IFACE_KEY = 300,
  COMMUNITY_KEY = 301,
  IFDESCR_KEY = 302,
  IFTYPE_KEY = 303,
  IFMTU_KEY = 304,
  IFSPEED72_KEY = 305,		// old, 32 bit value from Profiler 7.2
  IFMAC_KEY = 306,
  SNMP_VERSION_KEY = 307,
  IFSPEED_KEY = 308,		// 64 bit value in 7.5 for 10G support
  SLICEFLOWS_KEY = 309,
  IFALIAS_KEY = 310,
  IFACE_HIPRIORITY_KEY = 311,
  IP_KEY = 312,
  SYSNAME_KEY = 313,
  DNSRESOLVE_KEY = 314,
  RESTNODEOP_KEY = 315,
  CBQOS_CONFIG_KEY = 316,
  CBQOS_STATS_KEY = 317,

  TARS_INITIALIZED_KEY = 400,
  TARS_SUBMITTED_KEY,           // 401
  TARS_BYTES_KEY,               // 402
  TARS_ERRORS_KEY,              // 403
  TARS_ACTIVE_KEY,              // 404
  TARS_SKIPPED_KEY,             // 405
  
  SILENT_HOSTS_KEY,             // 406
  SILENT_SINCE_KEY,             // 407

  CONTROL_SENSOR_FLOWS_UNDELIVERED_KEY = 500, // value: uint32_t, the upper bound of dropped flow
                                              // count
  NTIMESLICE_KEY = 600,                       // NTIMESLICE value, uint32_t

  SEC_LEVEL_KEY = 601,
  SEC_NAME_KEY = 602,
  AUTH_PROTO_KEY = 603,
  AUTH_PSSWD_KEY = 604,
  PRIV_PROTO_KEY = 605,
  PRIV_PSSWD_KEY = 606,
  AUTH_MODE_KEY = 607,
  PRIV_MODE_KEY = 608,
  CTXT_NAME_KEY = 609,

  NETFLOW_FLOW_KEY = 610,
  MGMT_PORT_KEY = 611,
  CONTROL_PORT_KEY = 612,
  PEER_VENDOR_KEY = 613,
  PEER_MODEL_KEY = 614,
  PEER_VERSION_KEY = 615,
  NETFLOW_RAW_FLOW_KEY = 616,

  FLOW100 = 700,
  FLOW_SENSOR108 = 701,
  FLOW_INTELRG = 702,
  FLOW105 = 703,

  SENSOR_CONNECTIONS_KEY = 704,
  FLOW106 = 705,
  FLOW107 = 706,
  BGP_AS_KEY = 707,    // for snmp device bgp polling

  DISPATCHER_FLOW_LIMIT = 708, // for dispatcher last minute stats
  DISPATCHER_N_FLOWS = 709,
  DISPATCHER_OVERFLOW_LIMIT = 710,
  DISPATCHER_N_OVERFLOWS = 711,

  APP_MAPPING_KEY = 712,

  FLOW108 = 713,
  FLOW109 = 714,

  REPORTED_PEER_INFO_KEY = 715,
  RAWFLOWTOAGGREGATE_KEY = 716,

  TRACKED_INTERFACES_KEY = 717,
  RAWFLOWCOUNT_KEY       = 718,
  RAWFLOWRESULT_KEY      = 719,
  PROXY_SERVER_KEY       = 720,
  RESET_SENSOR_CONNECTIONS_KEY  = 721,
  // skip 722 as it is reserved in downstream ipv6-dev
  IPX_KEY                = 723,
  REMOTE_NODE_TYPE_KEY   = 724,
  REMOTE_SENSOR_TYPE_KEY = 725,
  MNMP_CONNECTION_STATUS_KEY = 726,
  REMOTE_STATUS_KEY = 727,
  //FLOW =728,   //Added in SD WAN
  //UPLINK_STATS_KEY=729, //Added in SD WAN
  //PATH_STATS_KEY=730,   //Added in SD WAN  
  OAUTH_KEY =731,
  FLOW = 732,   // Coracle
  MGMT_TIME_STATUS = 733
};

struct NTPStatus {
  unsigned long server;
  char status;
  float offset;
  
  NTPStatus() : server(0), status(' '), offset(0) { }
  NTPStatus(const unsigned long& s, char st, float o) : 
    server(s), status(st), offset(o) { }
};

inline std::ostringstream&
operator <<(std::ostringstream &sa, const NTPStatus &st)
{
  sa << st.server << " '" << st.status << "' " << st.offset;
  return sa;
}

typedef int Key;
class KeyMap;

class TLV {
public:
  TLV();
  TLV(const TLV &);
  TLV(Key);
  template <typename T> TLV(Key, T);
  TLV(Key, const char *);
  ~TLV()			{ delete[] _value; }
  TLV &operator=(const TLV &);
  static const TLV &null_tlv()		{ return the_null_tlv; }
  
  operator bool() const;

  friend bool operator==(const TLV &k1, const TLV &k2);

  Key key() const			{ return _key; }
  int length() const			{ return _length; }
  const unsigned char *value() const	{ return _value; }

  // values are zero-padded so that length is a multiple of 4
  void set_value(const unsigned char *v, unsigned len);
  unsigned char *alloc_value(unsigned len);
  template <typename T> void set_value(T v);
  template <typename T> bool get_value(T &v) const;

  char char_value() const { return _value ? _value[0] : 0; } 
  bool bool_value() const { return _value ? (bool)_value[0] : false; }
  unsigned unsigned_value() const { unsigned v = 0; get_value(v); return v; } 
  long long_value() const  { long v = 0; get_value(v); return v; } 
  uint64_t ulonglong_value() const { uint64_t v = 0; get_value(v); return v; } 
  float float_value() const { float v = 0; get_value(v); return v; } 
  time_t time_t_value() const { time_t v = 0; get_value(v); return v; } 
  std::string string_value() const;
  
  std::string s() const;

  int serial_size() const		{ return _length + keylen + lenlen; }
  int write(unsigned char *buf, int buflen) const;
  int read(const unsigned char *buf, int buflen);

private:

  static const int keylen = sizeof(unsigned);
  static const int lenlen = sizeof(unsigned);

  Key _key;
  int _length;
  unsigned char *_value;

  static TLV the_null_tlv;
  
  void _pad(unsigned char *c, int l);
  int _align(int l);

  friend class MNMPMessage;
};

template<typename T> inline
TLV::TLV(Key k, T value)
  : _key(k), _length(0), _value(0)
{
  set_value(value);
}

template <typename T> inline void
TLV::set_value(T v)
{
  set_value((unsigned char *)&v, sizeof(v));
}

template <typename T> inline bool
TLV::get_value(T &v) const
{
  if (!_value || _length != sizeof(v))
    return false;
  v = *((T *)_value);
  return true;
}

inline
TLV::operator bool() const
{
  return (_key != UNDEFINED_KEY) && _length && _value;
}

inline bool
operator==(const TLV &k1, const TLV &k2)
{
  if (k1._key != k2._key)
    return false;
  if (k1._length != k2._length)
    return false;
  return memcmp(k1._value, k2._value, k1._length) == 0;
}

class KeyMap {
public:
  KeyMap()				{ }
  ~KeyMap() 				{ }

  void add_key(const TLV &tlv)		{ _tlvs.push_back(tlv); }
  TLV &alloc_key(Key k);
  void clear()				{ _tlvs.clear(); }
  int size() const                      { return _tlvs.size(); }
  bool reserve(int n)		        { _tlvs.reserve(n); return true; }

  // return first matching TLV
  const TLV &operator[](Key) const;
  const TLV &get_single(Key kt) const { return (*this)[kt]; }
  const TLV *findp(Key) const;
  TLV *findp(Key);

  // fetch all matching TLVs; return count
  int get_multiple(Key, std::vector<TLV> &) const;

  // serialization
  int serial_size() const;
  int write(unsigned char *buf, int buflen, const Key *ignore = 0) const;
  int read(const unsigned char *buf, int buflen);
  std::string s() const;

  class iterator { public:
    iterator(const KeyMap *km)		: _km(km), _i(0), _size(_km->_tlvs.size()) { }
    ~iterator()				{ }

    operator bool() const		{ return _i < _size; }
    
    const TLV &operator*() const	{ return _km->_tlvs[_i]; }
    const TLV *operator->() const	{ return &_km->_tlvs[_i]; }
    const TLV &value() const		{ return _km->_tlvs[_i]; }
    
    void operator++(int)		{ _i++; }
    void operator++()			{ (*this)++; }

   private:
    const KeyMap *_km;
    int _i;
    int _size;
  };

  iterator first() const		{ return iterator(this); }
  
 private:
  std::vector<TLV> _tlvs;

  friend class iterator;
};

  
inline TLV &
KeyMap::alloc_key(Key k)
{ 
  TLV tlv(k);
  _tlvs.push_back(tlv);
  return _tlvs.back();
}

inline int
KeyMap::serial_size() const
{
  int len = 0;
  for (KeyMap::iterator i(this); i; i++)
    len += i.value().serial_size();
  return len;
}

inline unsigned
char2unsigned(const unsigned char *c)
{
  return *((unsigned *)c);
}

inline void
unsigned2char(unsigned char *c, unsigned val)
{
  *(unsigned *)c = val;
}

inline uint64_t
char2ull(const unsigned char *c)
{
  return *((uint64_t *)c);
}

inline void
ull2char(unsigned char *c, uint64_t val)
{
  *(uint64_t *)c = val;
}
