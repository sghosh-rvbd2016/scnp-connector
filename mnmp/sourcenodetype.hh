// see profiler_data.sql and profiler-update-*-sql source_node_types table
// see tools/Mazu/Config.pm constant declarations
class SourceNodeType { public:
  typedef enum {
    //
    // TopoCell types. 
    //   1. Because its _cell_type is a 5-bit wide bitfield, any
    //      modification/addition to this enum will need to take that into
    //      account.
    //   2. new type to name mapping needs to be added into source_node_types db
    //   3. new type to name mapping needs to be added into lib/mazu/devifaceapi.cc
    //
    MAZU_EMPTY    = 0,
    SENSOR        = 1, 
    NETFLOW       = 2, 
    SFLOW         = 3, 
    PACKETEER     = 4, 
    RG            = 5, 
    VLAN          = 6,
    FLOW_REPLAYER = 7, 
    SENSOR_VE     = 8, 
    STEELHEAD     = 9, // shark on SH
    EXPRESS       = 10,
    SHARK         = 11, 
    VSHARK        = 12,
    RG_VE         = 13,
    EXPRESS_SHARK = 14,
    ARX           = 15,
    ALLOY         = 16,
    VALLOY        = 17,
    SCM           = 18, // SteelConnect Manager
    MAX_TOPO_TYPE = 19,
    
    //
    // Types used outside TopoCell
    //

    // application source type
    NBAR          = 33,
    APPFLOW       = 34,
        
    // When the system is express and setting's CTRL_IP_ADDR is equal
    // to this node's ip the type is changed to this type (for display purposes on UI)
    // see TopoNodeData::get_display_type()
    EXPRESS_LOCAL = 101, 
    
    // When the version is one of {5.1, 9.1, 9.2} 
    // then type NETFLOW is changed to this type (for display purposes on UI)
    // see TopoNodeData::get_display_type()
    SH_NETFLOW    = 102, 

    // flow pool (not a real source type, an aggregator of flows from flow collectors)
    FLOW_POOL = 103
  } nodetype_t;
  
  static std::string s(nodetype_t type);
  static nodetype_t str_to_type(std::string type);
  static bool is_sensor(nodetype_t type);
  static bool is_shark(nodetype_t type);
  static bool is_alloy(nodetype_t type);
  static bool is_scm(nodetype_t type);
  static bool is_virtual(nodetype_t type);
  static bool is_mnmp_netflow_source(nodetype_t type);
  static bool has_outbound_speed(nodetype_t type);
  static bool use_host_rcm(nodetype_t type);
  static void get_nodetypes(std::vector<nodetype_t> &types);
  static bool valid_app_topo_type(unsigned t);
  static std::string flow_type(nodetype_t type);
};

inline std::string
SourceNodeType::s(nodetype_t type)
{
  switch(type) {
  case SENSOR:		return "sensor";
  case NETFLOW:		return "netflow";
  case SFLOW:		return "sflow";
  case PACKETEER:	return "packeteer";
  case RG:              return "rg";
  case VLAN:		return "vlan";
  case FLOW_REPLAYER:	return "flow replayer";
  case MAZU_EMPTY:	return "null";
  case SENSOR_VE:       return "sensorve";
  case STEELHEAD:       return "steelhead";
  case EXPRESS:         return "express";
  case SHARK:           return "shark";
  case VSHARK:          return "vshark";
  case RG_VE:           return "rgve";
  case EXPRESS_SHARK:   return "sharkexpress";
  case EXPRESS_LOCAL:   return "local sensor";
  case SH_NETFLOW:      return "sh netflow";
  case ARX:             return "arx";
  case ALLOY:           return "alloy";
  case VALLOY:          return "valloy";
  case SCM:             return "steelconnect manager";
  case NBAR:            return "nbar";
  case APPFLOW:         return "appflow";
  case FLOW_POOL:       return "flow pool";
  default:              return "unknown";
  };
}

inline SourceNodeType::nodetype_t
SourceNodeType::str_to_type(std::string type)
{
  if (type == "sensor")                return SENSOR;
  else if (type == "netflow")          return NETFLOW;
  else if (type == "sflow")            return SFLOW;
  else if (type == "packeteer")        return PACKETEER;
  else if (type == "rg")               return RG;
  else if (type == "vlan")             return VLAN;
  else if (type == "flow replayer")    return FLOW_REPLAYER;
  else if (type == "null")             return MAZU_EMPTY;
  else if (type == "sensorve")         return SENSOR_VE;
  else if (type == "steelhead")        return STEELHEAD;
  else if (type == "express")          return EXPRESS;
  else if (type == "shark")            return SHARK;
  else if (type == "vshark")           return VSHARK;
  else if (type == "rgve")             return RG_VE;
  else if (type == "sharkexpress")     return EXPRESS_SHARK;
  else if (type == "local sensor")     return EXPRESS_LOCAL;
  else if (type == "sh netflow")       return SH_NETFLOW;
  else if (type == "arx")              return ARX;
  else if (type == "alloy")            return ALLOY;
  else if (type == "valloy")           return VALLOY;
  else if (type == "steelconnect manager") return SCM;
  else if (type == "nbar")             return NBAR;
  else if (type == "appflow")          return APPFLOW;
  else if (type == "flow pool")        return FLOW_POOL;
  else                                 return MAZU_EMPTY;
}

namespace FlowTypes {
  static const std::string FLOWTYPE_NETFLOW("NetFlow");
  static const std::string FLOWTYPE_SFLOW("SFlow");
  static const std::string FLOWTYPE_PACKETEER("Packeteer");
  static const std::string FLOWTYPE_RIVERBED_STEELFLOW("Riverbed SteelFlow");
}

inline std::string
SourceNodeType::flow_type(nodetype_t type)
{
  switch (type) {
  case SHARK:
  case VSHARK:
  case EXPRESS_SHARK:
  case STEELHEAD:
  case SH_NETFLOW:
  case ALLOY:
  case VALLOY:
  case SCM:
    return FlowTypes::FLOWTYPE_RIVERBED_STEELFLOW;
  case NETFLOW:
    return FlowTypes::FLOWTYPE_NETFLOW;
  case SFLOW:
    return FlowTypes::FLOWTYPE_SFLOW;
  case PACKETEER:
    return FlowTypes::FLOWTYPE_PACKETEER;
  default:
    return SourceNodeType::s(type);
  }
}

inline bool
SourceNodeType::is_sensor(nodetype_t type)
{
  return (type == SENSOR || type == SENSOR_VE || type == EXPRESS || is_shark(type));
}

inline bool
SourceNodeType::is_shark(nodetype_t type)
{
  return (type == SHARK || type == VSHARK
            || type == EXPRESS_SHARK
            || type == STEELHEAD
            || type == ARX || is_alloy(type));
}

inline bool
SourceNodeType::is_alloy(nodetype_t type)
{
  return (type == ALLOY || type == VALLOY);
}

inline bool
SourceNodeType::is_scm(nodetype_t type)
{
  return (type == SCM);
}

inline bool
SourceNodeType::is_virtual(nodetype_t type)
{
  return (type == SENSOR_VE || type == VSHARK || type == RG_VE || type == VALLOY);
}

inline bool
SourceNodeType::is_mnmp_netflow_source(nodetype_t type)
{
  switch (type) {
    case SHARK:
    case VSHARK:
    case ALLOY:
    case VALLOY:
    case EXPRESS_SHARK:
      return true;
    default:
      return false;
  }
  return false;
}

inline bool
SourceNodeType::has_outbound_speed(nodetype_t type)
{
  switch (type) {
    case SENSOR:
    case SENSOR_VE:
    case EXPRESS_LOCAL:
    case SHARK:
    case VSHARK:
    case VLAN:
    case EXPRESS:
    case EXPRESS_SHARK:
    case ARX:
    case ALLOY:
    case VALLOY:
    case STEELHEAD:
    case NBAR:
    case APPFLOW:
    case MAX_TOPO_TYPE:
    case FLOW_POOL:
      return false;
    case MAZU_EMPTY:
    case NETFLOW:
    case SFLOW:
    case PACKETEER:
    case RG:
    case RG_VE:
    case FLOW_REPLAYER:
    case SH_NETFLOW:
    case SCM:
      return true;
  }
  return true;
}

// UI will use the host RCM (not device) for these node types
// bug 96208
inline bool
SourceNodeType::use_host_rcm(nodetype_t type)
{
  switch (type) {
    case RG:
    case RG_VE:
    case EXPRESS_LOCAL:
    case EXPRESS:
    case EXPRESS_SHARK:
    case STEELHEAD:
      return true;
    case ARX:
    case ALLOY:
    case VALLOY:
    case SCM:
    case SENSOR:
    case SENSOR_VE:
    case MAZU_EMPTY:
    case NETFLOW:
    case SFLOW:
    case PACKETEER:
    case FLOW_REPLAYER:
    case SH_NETFLOW:
    case SHARK:
    case VSHARK:
    case VLAN:
    case NBAR:
    case APPFLOW:
    case MAX_TOPO_TYPE:
    case FLOW_POOL:
      return false;
  }
  return false;
}

// returns all types
inline void
SourceNodeType::get_nodetypes(std::vector<nodetype_t> &types)
{
  types.clear();
  types.push_back(MAZU_EMPTY);
  types.push_back(SENSOR);
  types.push_back(NETFLOW);
  types.push_back(SFLOW);
  types.push_back(PACKETEER);
  types.push_back(RG);
  types.push_back(VLAN);
  types.push_back(FLOW_REPLAYER);
  types.push_back(SENSOR_VE);
  types.push_back(STEELHEAD);
  types.push_back(EXPRESS);
  types.push_back(SHARK);
  types.push_back(VSHARK);
  types.push_back(RG_VE);
  types.push_back(EXPRESS_SHARK);
  types.push_back(ARX);
  types.push_back(ALLOY);
  types.push_back(VALLOY);
  types.push_back(SCM);
  types.push_back(EXPRESS_LOCAL);
  types.push_back(SH_NETFLOW);
  types.push_back(NBAR);
  types.push_back(APPFLOW);
}

inline bool 
SourceNodeType::valid_app_topo_type(unsigned t)
{   
  const nodetype_t type = (nodetype_t)t;
  if (is_shark(type))
    return true;

  switch (type) {
    case NETFLOW:
    case NBAR:
    case APPFLOW:
    case RG:
    case SCM:
      return true;
    default:
      return false;
  }
}

namespace RVBDNetflowVersions {
    static const std::string RVBD_v5("5.1");
    static const std::string RVBD_v9("9.1");
    static const std::string RVBD_CASCADE_FLOW("9.2");
}

class SourceNodeInfo : public SourceNodeType {
    public:
        SourceNodeInfo(const nodetype_t type = MAZU_EMPTY, const char *version = "N/A") : _type(type)
                                                { strncpy(_version, version, sizeof(_version));
                                                  _version[sizeof(_version) - 1]= '\0'; }

        nodetype_t type() const                 { return _type; }
        void set_type(const nodetype_t &type)   { _type = type; }

        const char* version() const             { return _version; }
        void set_version(const char *version) 
                                                { strncpy(_version, version, sizeof(_version));  
                                                  _version[sizeof(_version) - 1]= '\0'; }

        std::string s() const;

        static bool is_rest_type(SourceNodeType::nodetype_t type); 
        static bool is_rest_version(const std::string &version);
        static bool is_rest_candidate(SourceNodeType::nodetype_t type, 
                                      const std::string &version);

    private:
        nodetype_t      _type;
        // for now these are NetFlow version(s).
        char            _version[8];
};

class SourceNodeInfoExtended : public SourceNodeInfo {
  typedef SourceNodeInfo inherited;
public:
  SourceNodeInfoExtended(const nodetype_t type = MAZU_EMPTY, const char *version = "N/A",
			 const int32_t nflows = 0) : inherited(type, version),
						     _nflows(nflows) {}
  int32_t nflows() const                       { return _nflows; }
  void set_nflows(int32_t nflows)              { _nflows = nflows; }

private:
  int32_t _nflows;
};
    
inline std::string
SourceNodeInfo::s() const
{
    std::ostringstream str;

    str << SourceNodeType::s(_type) << ", version "
        << _version;

    return str.str();

}

inline bool
SourceNodeInfo::is_rest_type(nodetype_t type)
{
  return (type == SourceNodeType::NETFLOW || type == SourceNodeType::SCM || SourceNodeType::is_shark(type));
}

// version can be a comma separated list
inline bool
SourceNodeInfo::is_rest_version(const std::string &version)
{
  return (version.find(RVBDNetflowVersions::RVBD_v5) >= 0 ||
          version.find(RVBDNetflowVersions::RVBD_v9) >=0 ||
          version.find(RVBDNetflowVersions::RVBD_CASCADE_FLOW) >=0);
}

inline bool 
SourceNodeInfo::is_rest_candidate(SourceNodeType::nodetype_t type, 
                                  const std::string &version) {
    // skip SCM for now as we don't support its REST polling yet
    return (!SourceNodeType::is_scm(type) &&
            (SourceNodeType::is_shark(type) || is_rest_version(version)));
}

typedef enum { VXLAN_NONE = 0, VXLAN_INTRA_HOST, VXLAN_INTER_HOST, VXLAN_TUNNEL } vxlan_flow_type_t;
inline const std::string vxlan_flow_type2str(uint type)
{ 
    switch (type) {
        case VXLAN_NONE:          return "non-vxlan";
        case VXLAN_INTRA_HOST:    return "vxlan-intra-host";
        case VXLAN_INTER_HOST:    return "vxlan-inter-host";
        case VXLAN_TUNNEL:        return "vxlan-tunnel";
        default:                  return "unknown";
    };
}

inline uint vxlan_flow_str2type(const std::string &type)
{ 
    if (type == "vxlan-intra-host") return VXLAN_INTRA_HOST;
    else if (type == "vxlan-inter-host") return VXLAN_INTER_HOST;
    else if (type == "vxlan-tunnel") return VXLAN_TUNNEL;
    else return VXLAN_NONE;
}

inline bool is_vxlan_tunnel_flow(const uint t)
{ 
    return t == VXLAN_TUNNEL; 
}

inline bool is_vxlan_tenant_flow(const uint t)
{
    return (t == VXLAN_INTRA_HOST || t == VXLAN_INTER_HOST); 
}

