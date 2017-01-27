#include "tlv.hh"
#include "compressor.hh"
#include "sourcenodetype.hh"

typedef uint64_t NodeID;
typedef uint64_t NodeType;
const NodeType NODE_NONE = 0;
const NodeType NODE_ALL = 1;
const NodeType NODE_SENSOR = 2;
const NodeType NODE_DISPATCHER = 3;
const NodeType NODE_ANALYZER = 4;
const NodeType NODE_EVENTMANAGER = 5;
const NodeType NODE_RBANALYZER = 6;
const NodeType NODE_OPANALYZER = 7;
const NodeType NODE_DASHBOARDD = 8;
const NodeType NODE_HEALTHD = 9;
const NodeType NODE_RESTDEVICEMANAGER = 10;
const NodeType NODE_FRAWFLOW = 11;
const NodeType NUM_NODES = NODE_FRAWFLOW + 1;

static const uint32_t MNMP_VERSION =        (((((('T' <<8) + 'P') <<8) + '1') <<8)) + '1'; // = 'TP11';
static const uint32_t MNMP_IR84_VERSION =   (((((('I' <<8) + 'R') <<8) + '8') <<8)) + '4'; // = 'IR84';
static const uint32_t MNMP_FLOW82_VERSION = (((((('T' <<8) + 'P') <<8) + '8') <<8)) + '2'; // = 'TP82';
static const uint32_t MNMP_FLOW81_VERSION = (((((('T' <<8) + 'P') <<8) + '8') <<8)) + '1'; // = 'TP81';
static const uint32_t MNMP_FLOW72_VERSION = (((((('T' <<8) + 'P') <<8) + 'L') <<8)) + 'G'; // = 'TPLG';

enum {
  MN_UNDEFINED                      = 0x00,
  MN_HELLO                          = 0x01,
  MN_WELCOME                        = 0x03,
  MN_GOODBYE                        = 0x04,

  MN_BEGINSLICE_MESSAGE             = 1341,
  MN_ENDSLICE_MESSAGE               = 1342,
  MN_FLOWS_MESSAGE                  = 1349,
  MN_FLOW_MAPPINGS_MESSAGE          = 1350,
  MN_ANOMALY_MESSAGE                = 1351,
  MN_SERVER_PORT_MESSAGE            = 1352,
  MN_NTP_MESSAGE                    = 1353,
  MN_SIGNATURES_MESSAGE             = 1354,
  MN_RBREQUEST_MESSAGE              = 1355,
  MN_SOURCES_MESSAGE                = 1360,
  MN_PACKETEER_MAPPINGS_MESSAGE     = 1361,
  MN_IFACE_RESOLVE_REQUEST_MESSAGE  = 1362,
  MN_IFACE_RESOLVE_RESPONSE_MESSAGE = 1363,
  MN_SSH_KEY_EXCHANGE_MESSAGE       = 1364,
  // MN_SLICEFLOWS_MESSAGE          = 1365,
  MN_TARARI_STATUS_MESSAGE          = 1366,
  MN_NBAR_MAPPINGS_MESSAGE          = 1367,
  MN_SILENTHOSTS_MESSAGE            = 1368,
  MN_CONTROL_MESSAGE                = 1369,
  MN_NODE_RESOLVE_REQUEST_MESSAGE   = 1370,
  MN_NODE_RESOLVE_RESPONSE_MESSAGE  = 1371,
  MN_ANOMALY_DONE_MESSAGE           = 1372,
  MN_FLOW_LOGGING_DONE_MESSAGE      = 1373,
  MN_NETFLOW_FLOW_MESSAGE           = 1374,
  MN_RESOLVED_IP_TO_DNS_MESSAGE     = 1375,
  MN_REFRESH_DNSNAMES_MESSAGE       = 1376,
  MN_CLEAR_DNS_DEVICE_CACHE         = 1377,
  MN_STEELHEAD_MAPPINGS_MESSAGE     = 1378, // used ONLY in Polacre+ (deprecated)
  MN_REST_NODES_MESSAGE             = 1379,
  MN_REST_NODES_PRIORITY_REFRESH_REQUEST_MESSAGE    = 1380,
  MN_REST_NODES_PRIORITY_REFRESH_RESPONSE_MESSAGE   = 1381,
  MN_SENSOR_CONNECTIONS_MESSAGE     = 1382,
  MN_FLOW_LIMIT_STATS_MESSAGE       = 1383,
  MN_APP_MAPPINGS_MESSAGE           = 1384,
  MN_ONE_MIN_ROLLUP_LOGGING_DONE_MESSAGE = 1385,
  MN_REPORTED_PEER_INFO_MESSAGE     = 1386,
  MN_FLOWS_TO_AGGREGATE_MESSAGE     = 1387,
  MN_TRACKED_INTERFACES_MESSAGE     = 1388,
  // MN_BEGINSLICE_TO_AGGREGATE_MESSAGE= 1389, // not-used
  // MN_ENDSLICE_TO_AGGREGATE_MESSAGE  = 1390, // not-used
  MN_CBQOS_CONFIG_REQUEST_MESSAGE   = 1391,
  MN_CBQOS_CONFIG_RESPONSE_MESSAGE  = 1392,
  MN_CBQOS_STATS_REQUEST_MESSAGE    = 1393,
  MN_CBQOS_STATS_RESPONSE_MESSAGE   = 1394,
  MN_RESET_SENSOR_CONNECTIONS_MESSAGE  = 1395,
  MN_REMOTE_STATUS_MESSAGE          = 1396,
  //MN_UPLINK_STATS_MESSAGE=1397, // used in SD WAN
  //MN_PATH_STATS_MESSAGE=1398, // used in SD WAN
  MN_ALLOY_OAUTH_MESSAGE            = 1399,
  MN_IFACE_REST_RESOLVE_REQUEST_MESSAGE = 1400,
  MN_NODE_REST_RESOLVE_REQUEST_MESSAGE = 1401,
  MN_MGMT_TIME_STATUS_MESSAGE       = 1402
};

std::string hex_s(const void* buf, size_t len);

typedef int MessageType;

typedef struct {
  time_t t;
  long int r;
} Challenge;

class MNMPMessage {
public:

  enum {
    COMPRESSION_NONE = 0,
    COMPRESSION_ZLIB = 1,
    COMPRESSION_LZ4  = 2
  };
  typedef uint32_t CompressionType;

  enum { ERR = -1, SSLERR = -2, AGAIN = -3, DONE = -4 };

  explicit MNMPMessage(MessageType m = MN_UNDEFINED,
                       NodeID sourceid = 0, NodeID destid = 0);
  virtual ~MNMPMessage() { if(_buf) delete[] _buf; }

  MNMPMessage(const MNMPMessage &);
  MNMPMessage &operator=(const MNMPMessage &);

  NodeID src() const                    { return _src; }
  void set_src(NodeID n)                { _src = n; }
  NodeID dst() const                    { return _dst; }
  void set_dst(NodeID n)                { _dst = n; }
  static uint32_t node_mnmp_version(NodeID n);

  MessageType type() const              { return _type; }
  void set_type(MessageType t)          { _type = t; }

  NodeType src_type() const;
  std::string src_sensor_type() const;
  std::string src_name() const;
  uint32_t version() const { return _header.version; }

  CompressionType compression() const      { return _compression; }
  void set_compression(CompressionType c)  { _compression = c; }

  void insert(const TLV &t)             { _keys.add_key(t); }
  void clear_keys()                     { _keys.clear(); }
  bool reserve_keys(int n)              { return _keys.reserve(n); }

  int n_tlvs() const                    { return _keys.size(); }

  const KeyMap *keys() const            { return &_keys; }
  const TLV &operator[](Key k) const    { return _keys[k]; }

  bool exists(Key k) const              { return find_key(k) != 0; }
  const TLV *find_key(Key k) const      { return _keys.findp(k); }
  TLV *find_key(Key k)                  { return _keys.findp(k); }
  void find_keys(Key k, std::vector<TLV>& values) const {
    _keys.get_multiple(k, values);
  }

  int read(StreamSocket &fd);
  int write(StreamSocket &fd);
  int max_serial_size() const;  // estimate, not counting compression
  unsigned uncompressed_len() const { return _uncompressed_len; }
  unsigned wire_len() const { return _wirelen; }

  std::string type_string() const;
  std::string s() const;

  void switch_source_dest();

  // utility methods for MNMP authentication
  // adds and returns a default challenge TLV (to be deleted by the caller)
  Challenge add_challenge();
  // adds a MD5_AUTH_KEY TLV for the password+challenge
  void add_auth(const char *password, MNMPMessage *challenge_message);
  // check if MD5_AUTH_KEY TLV is present and is indeed for the password
  bool check_auth(const char *password, Challenge challenge);

  // Configuration affecting all subsequent messages.
  static void set_lz4_enabled( bool newstate ) { _lz4_enabled = newstate; }
  static bool get_lz4_enabled( ) { return _lz4_enabled; }

  static const std::string NULL_VERSION;
  static std::string version_s(const uint32_t &version, const SourceNodeType::nodetype_t &type);

protected:
  MessageType _type;
  NodeID _src;
  NodeID _dst;
  CompressionType _compression;
  unsigned _uncompressed_len;   // original length of the message
  unsigned _wirelen;  // length of the message when it was transmitted

  struct {
    uint32_t version;
    uint32_t length;
  } _header;
  uint8_t *_buf;
  unsigned _len;
  unsigned _pos;
  unsigned _hpos;

  KeyMap _keys;

  int make_from_char(const unsigned char *data, unsigned bytesleft);
  int char2tlvs(const unsigned char *, int, unsigned);
  int write(unsigned char *buf, int buflen) const;

  uint32_t max_compressed_len( uint32_t in_len ) const;

private:
  static bool _lz4_enabled;
  LZ4Compressor _lz4_compressor;
  ZLIBCompressor _zlib_compressor;
  int write_compressed( const BlockCompressor &compressor, int in_len,
                        unsigned char *buf, int buflen, int pos ) const;
  CompressionType compression_selection() const;
};

inline std::ostringstream&
operator<<(std::ostringstream &sa, const MNMPMessage &m)
{
  sa << m.s();
  return sa;
}

class HelloMessage : public MNMPMessage {
public:
  HelloMessage(NodeID from, NodeID to, NodeType,
               const std::string &name, const std::string &sensor_type);
};

class WelcomeMessage : public MNMPMessage {
public:
  WelcomeMessage(NodeID from, NodeID to, NodeType,
                 const std::string &name, const std::string &sensor_type);
};

class GoodbyeMessage : public MNMPMessage {
public:
  GoodbyeMessage(NodeID from);
};

class NetflowFlowsMessage : public MNMPMessage {
public:
  NetflowFlowsMessage(NodeID s, NodeID d);
  void add(const unsigned char *packet, size_t len);
};

