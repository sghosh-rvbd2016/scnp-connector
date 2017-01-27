#include "socket.hh"
#include "mnmp.hh"
#include "safequeue.hh"
#include <thread>

class MNMPClient
{
public:

  MNMPClient(const NodeID &id,
             const std::string &server,
             unsigned server_port,
	     const unsigned &compression,
             const SSLContext &ssl_ctx)
    : _peer(server.c_str(), server_port),
      _running(false),
      _compression(compression),
      _last_in_count(0),
      _last_out_count(0),
      _id(id),
      _ssl(ssl_ctx),
      _socket(_ssl),
      _server(server)
  {
    connect();
  }

  bool close();
  bool connect();
  bool connected();
  int handshake();
  
  void set_mnmp_queue_size(size_t s) { _max_out_queue = s; }

  size_t mnmp_queue_size();

  size_t mnmp_queue_high_watermark() { return _out_queue.high_watermark(); }

  void handle_message(const MNMPMessage &msg);

  void send_message(MNMPMessage *m);

  NodeID id() const { return _id; }

  int write_message(MNMPMessage &msg) { return msg.write(_socket); }

  int read_message(MNMPMessage &msg) { return msg.read(_socket); }
  
  void mnmp_tx_loop();
  void mnmp_rx_loop();
  
  void main_loop();

protected:
  InetSockAddrIn _peer;
  bool _running;
  unsigned _compression;
  std::mutex _mutex;
  size_t _max_out_queue;
  unsigned _last_in_count;
  unsigned _last_out_count;

private:
  NodeID _id;
  const SSLContext &_ssl; 
  SSLSocket _socket;
  std::string _server;
  SafeQueue<MNMPMessage*> _out_queue;
};
