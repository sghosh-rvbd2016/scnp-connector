#include "mnmp/socket.hh"
#include "udpserver.hh"
#include <unistd.h>

int
UDPServer::read(unsigned char *data, int max_length)
{
  sockaddr_in peer;
  socklen_t peerlen;

  return read(data, max_length, peer, peerlen);
}

int
UDPServer::read(unsigned char *data, int max_length, sockaddr_in &peer, socklen_t &peerlen)
{
  if (!_bound)
    return 0;

  int len = _socket.recvfrom(data, max_length,
                             (struct sockaddr*)&peer, &peerlen);
  if (len > 0)
    data[len] = 0;

  return len;
}

void
UDPServer::rx_loop()
{
  Packet *p = NULL;
  while(1)
  {
    if (!p)
      p = new Packet();
    if (p) {
       int len = read(p->data, sizeof(p->data));
       if (len > 0) {
         p->length = len;
         if (_in_queue.size() >= _max_in_queue) {
           AT_MOST_ONCE_A_MINUTE(INFOF("UDPServer: inbound queue is full, dropping"));
           Packet *old_p = _in_queue.pop();
           delete old_p;
         }
         _in_queue.push(p);
         p = NULL;
         continue;
       }
    } else {
      AT_MOST_ONCE_A_MINUTE(DEBUGF("UDPServer: failed to allocate a packet!"));
    }
    usleep(1000); 
    std::unique_lock<std::mutex> mlock(_mutex);
    if (!_running)
      return; 
  }
}

void
UDPServer::stop()
{
  DEBUGF("Stopping UDPServer..");
  std::unique_lock<std::mutex> mlock(_mutex);
  _running = false;
  mlock.unlock();
  _in_queue_thread.join();
  DEBUGF("Stopped UDPServer");
}

size_t
UDPServer::queue_size()
{
  std::unique_lock<std::mutex> mlock(_mutex);
  return _max_in_queue;
}

