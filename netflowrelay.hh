#include "mnmp/mnmpclient.hh"
#include "udpserver.hh"

//
// A simple MNMP client implementation to read Netflow packets 
// from a UDPServer and relay them to a connected NetProfiler,
// Flow Gateway, or Insights instance over SSL. 
//
class NetflowRelay : public MNMPClient
{
public:

  NetflowRelay(const NodeID &id,
             const std::string &mnmp_server,
             unsigned mnmp_port,
	     const unsigned &compression,
             const SSLContext &ssl_ctx,
             const std::string &udp_addr,
             const Port &udp_port)
    :  MNMPClient(id, mnmp_server, mnmp_port, compression, ssl_ctx),
      _last_update(time(0)),
      _max_netflow_queue(1000),
      _udp_addr(udp_addr),
      _udp_port(udp_port)
  {
    _last_update = _last_update - (_last_update % 60);
  }

  void set_netflow_queue_size(size_t s) { _max_netflow_queue = s; }

  void main_loop();

  void update_stats(UDPServer &netflow_srouce);

  void clear_stats();

private:
  time_t _last_update;
  size_t _max_netflow_queue;
  std::string _udp_addr;
  Port _udp_port;
};
