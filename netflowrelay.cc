#include <ctime>
#include <unistd.h>
#include "netflowrelay.hh"
#define MAX_BUNDLE_SIZE 100
#define BACKOFF_USECS (10 * 1000)

void
NetflowRelay::main_loop()
{
  if (!connected())
    return;

  _running = true;

  std::thread tx(&NetflowRelay::mnmp_tx_loop, this);
  std::thread rx(&NetflowRelay::mnmp_rx_loop, this);

  UDPServer netflow_source(_udp_addr, _udp_port, _max_netflow_queue);

  if (!netflow_source.connected())
    ERRORF("could not open UDP port %u on address %s", _udp_port, _udp_addr.c_str());

  NetflowFlowsMessage *flows_msg = NULL;

  while (1)
  {
    int packets = 0;

    if (!flows_msg)
      flows_msg = new NetflowFlowsMessage(id(), 0);

    if (flows_msg) {
      flows_msg->set_compression(_compression);

      int ready = netflow_source.npackets_ready();

      int bundle_size = (ready < MAX_BUNDLE_SIZE) ? ready : MAX_BUNDLE_SIZE;

      for (int idx=0; idx < bundle_size; idx++) {

        UDPServer::Packet *packet = netflow_source.get_packet();

        if (packet) {
          flows_msg->add(packet->data, packet->length);
          packets++;
          _last_in_count++;
          delete packet;
        }
      }

      if (packets) {
        send_message(flows_msg);
        flows_msg = NULL;
        DEBUG2F("NetflowRelay::netflow_relay_loop sent NetFlowsMessage with %d packets",
                packets);
      } else if (!ready) {
        usleep(BACKOFF_USECS); // slight back-off
      }

    } else {
      AT_MOST_ONCE_A_MINUTE(
        DEBUGF("NetflowRelay::netflow_relay_loop failed to allocate a packet!"));
        continue;
    }  

    if (time(0) >= _last_update + 60)
      update_stats(netflow_source);

    std::unique_lock<std::mutex> mlock(_mutex);
    if (!_running || !netflow_source.connected())
      break;
    mlock.unlock();
  }

  DEBUGF("NetflowRelay::netflow_relay_loop: shutting down..");

  netflow_source.stop();

  close();

  tx.join();
  rx.join();

  DEBUGF("NetflowRelay::netflow_relay_loop: stopped");
}

void
NetflowRelay::update_stats(UDPServer &netflow_source)
{
  INFOF("slice %u: relayed %u datagrams (input %u, maxq in %u/%u out %u/%u)",
        (unsigned)_last_update, _last_out_count, _last_in_count,
        (unsigned)netflow_source.high_watermark(), (unsigned)netflow_source.queue_size(),
        (unsigned)mnmp_queue_high_watermark(), (unsigned)mnmp_queue_size());
  _last_update = time(0);
  _last_update = _last_update - (_last_update % 60);
  clear_stats();
  netflow_source.clear_stats();
  _last_in_count = 0;
  _last_out_count = 0;
}

void
NetflowRelay::clear_stats()
{
  std::unique_lock<std::mutex> mlock(_mutex);
  _last_in_count = 0;
  _last_out_count = 0;
}
