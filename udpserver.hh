#include "mnmp/socket.hh"
#include "mnmp/safequeue.hh"
#include <thread>
#ifndef UDP_SERVER_HH
#define UDP_SERVER_HH

//
// A simple UDP packet receiver that uses it's own thread to
// read UDP packets into a thread safe Queue for other tasks to consume
//
class UDPServer
{
public:

  class Packet
  {
  public:
    int length;
    unsigned char data[2048];
  };

  UDPServer(const std::string &address, unsigned port, size_t queue_size)
    : _socket(),
      _bound((SOCK_ERR != _socket.bind(InetSockAddrIn(address.c_str(), port)))),
      _running(true),
      _in_queue_thread(&UDPServer::rx_loop, this),
      _max_in_queue(1000)
  {
  }

  bool connected() const { return _bound; }

  void rx_loop();

  size_t high_watermark() { return _in_queue.high_watermark(); }

  void clear_stats() { _in_queue.clear_stats(); }

  size_t queue_size();

  size_t npackets_ready() { return _in_queue.size(); }

  Packet *get_packet() { return _in_queue.pop(); }

  void stop();

protected:

  int read(unsigned char *data, int max_length);

  int read(unsigned char *data, int max_length,
           sockaddr_in &peer, socklen_t &peerlen);

private:

  InetDGSocket _socket;
  bool _bound;
  bool _running;
  SafeQueue<Packet*> _in_queue;
  std::thread _in_queue_thread;
  size_t _max_in_queue;
  std::mutex _mutex;
};

#endif
