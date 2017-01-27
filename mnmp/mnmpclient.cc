#include <ctime>
#include <unistd.h>
#include "mnmpclient.hh"
#define BACKOFF_USECS (10 * 1000)

bool
MNMPClient::close() { 
  GoodbyeMessage *msg = new GoodbyeMessage(_id);

  send_message(msg);

  std::unique_lock<std::mutex> mlock(_mutex);
  _running = false;

  sleep(1);

  return (SOCK_OK == _socket.close());
}

bool
MNMPClient::connect()
{
  int state = _socket.connect(_peer);
      
  if (state == SOCK_ERR || state == SOCK_SSLERR) {
    DEBUGF("connection failed");
    _socket.close();
    return false;
  }

  int tries = 10;
  while(!connected() && tries-- > 0) {
    DEBUGF("waiting for MNMP to come up...");
    sleep(1);
  }

  if (!connected()) {
    INFOF("could not connect to server %s, retry", _server.c_str());
    return false;
  }

  handshake();

  return true;
}

bool
MNMPClient::connected()
{
  if (!_socket.is_connected())
    _socket.proceed();
  return _socket.is_connected();
}

int
MNMPClient::handshake()
{
  HelloMessage hello(_id, 0, NODE_SENSOR, "SCM", "mazu");

  hello.insert(TLV(NTIMESLICE_KEY, 3));

  return hello.write(_socket); 
}

void
MNMPClient::mnmp_rx_loop()
{
  while(1)
  {
    bool done = false;
    MNMPMessage msg_in;

    while(!done)
    {
      std::unique_lock<std::mutex> mlock(_mutex);
      if (!_running)
        return;
      switch(msg_in.read(_socket))
      {
        case MNMPMessage::DONE:
          mlock.unlock();
          handle_message(msg_in);
          done = true;
          break; 
        case MNMPMessage::AGAIN:
          mlock.unlock();
          usleep(BACKOFF_USECS); // slight back-off
          continue;
        case MNMPMessage::ERR:
          DEBUG2F("read message failed ERR");
          break;
        case MNMPMessage::SSLERR:
          DEBUG2F("read message failed SSLERR");
          break;
      }
      if (!done)
        _running = false;
    }

    sleep(1); // only process incoming message once a second
  }
}

void
MNMPClient::handle_message(const MNMPMessage &msg)
{
  switch(msg.type())
  {
    case MN_WELCOME:
      INFOF("Welcome message from %s (%llu) type %s",
             msg.src_name().c_str(), (long long unsigned)msg.src(),
             msg.src_sensor_type().c_str());
      break;
    default:
      AT_MOST_ONCE_A_MINUTE(
        DEBUG2F("unhandled MNMP message type=%s from %llu",
                msg.type_string().c_str(), (long long unsigned)msg.src()));
      break;
  }
}

void
MNMPClient::main_loop()
{
  connect();

  std::thread tx(&MNMPClient::mnmp_tx_loop, this);
  std::thread rx(&MNMPClient::mnmp_rx_loop, this);

  tx.join();
  rx.join();
}

void
MNMPClient::mnmp_tx_loop()
{
  while(1)
  {
    MNMPMessage *msg = _out_queue.pop();
    bool done = false;
    while(!done) {
      int ntlvs = msg->n_tlvs();
      std::unique_lock<std::mutex> mlock(_mutex);
      if (!_running)
        return;
      switch(write_message(*msg))
      {
        case MNMPMessage::DONE:
          mlock.unlock();
          _last_out_count += ntlvs;
          done = true;
          delete msg;
          break;
        case MNMPMessage::AGAIN:
          mlock.unlock();
          usleep(BACKOFF_USECS); // slight back-off
          continue;
        case MNMPMessage::ERR:
          DEBUG2F("write message failed ERR");
          break;
        case MNMPMessage::SSLERR:
          DEBUG2F("write message failed SSLERR");
          break;
      }
      if (!done)
        _running = false;
    }
  }
}

void
MNMPClient::send_message(MNMPMessage *m)
{
  if (_out_queue.size() >= _max_out_queue) {
    AT_MOST_ONCE_A_MINUTE(
      INFOF("MNMPClient::send_message: outbound queue full, dropping"));
    MNMPMessage *old_m = _out_queue.pop();
    delete old_m;   
  }
  _out_queue.push(m);
}

size_t
MNMPClient::mnmp_queue_size()
{
  std::unique_lock<std::mutex> mlock(_mutex);
  return _max_out_queue;
}
