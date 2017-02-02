#include "netflowrelay.hh"
#include "mnmp/logging.hh"
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// Global Variables and defaults
NodeID		MNMP_ID			= 0;
unsigned 	MNMP_SSL_PORT		= 41017;
std::string	MNMP_SERVER		= "";
int		MNMP_COMPRESSION	= MNMPMessage::COMPRESSION_LZ4;
std::string	SYSLOG_NAME		= "";
std::string	SSL_CERTIFICATE		= "/etc/npm/flowlogging/ssl/mnmp.pem";
std::string	SSL_TRUSTED_DIR		= "/etc/npm/flowlogging/ssl";
std::string	NETFLOW_ADDR            = "127.0.0.1";
unsigned 	NETFLOW_PORT		= 2055;
int		RETRY_CONNECT_DELAY_SECS= 60;
size_t		NETFLOW_QUEUE_SIZE	= 1000;
size_t		MNMP_QUEUE_SIZE		= 1000;

// resolve hostname to IP address
bool resolve_hostname(const std::string &hostname, std::string &hostaddr)
{
    struct hostent *tmp = gethostbyname(hostname.c_str());

    if (tmp && tmp->h_addr_list[0] != NULL) {
      hostaddr = inet_ntoa((struct in_addr)*((struct in_addr *)tmp->h_addr_list[0]));
      return true;
    }

    return false;
}

// Relay packets from a local UDP port to a NetProfiler over MNMP.
void do_netflow_relay_task()
{
  while(1)
  {
    SSLContext ssl_context(SSL_CERTIFICATE, SSL_TRUSTED_DIR, true);

    std::string mnmp_ip_address;

    if (!resolve_hostname(MNMP_SERVER, mnmp_ip_address)) {
      WARNINGF("failed to resolve host %s", MNMP_SERVER.c_str());
      mnmp_ip_address = MNMP_SERVER;
    }

    NetflowRelay client(MNMP_ID, mnmp_ip_address, MNMP_SSL_PORT,
                        MNMP_COMPRESSION, ssl_context,
                        NETFLOW_ADDR, NETFLOW_PORT);

    client.set_mnmp_queue_size(MNMP_QUEUE_SIZE);
    client.set_netflow_queue_size(NETFLOW_QUEUE_SIZE);

    client.main_loop();

    INFOF("no connection to server, retrying in %u seconds...",
          RETRY_CONNECT_DELAY_SECS);

    sleep(RETRY_CONNECT_DELAY_SECS); // connection failure, wait and re-establish
  }
}

void print_usage(const char *progname)
{
  printf("\nUsage: %s --id --netprofiler <hostname> [OPTIONS]\n\n\
Required Arguments:\n\
\n\
   --id <integer>		Set MNMP ID for this node.\n\
   --netprofiler <hostname|IP>	NetProfiler to connect to.\n\
   --netflow-relay              Connect and relay NetFlow records to NetProfiler.\n\
\n\
Optional Arguments:\n\
\n\
   --certificate <file>         SSL certificate to use for MNMP.\n\
   --debug[n]                   Log debug messages, level 2 or 3 is optional.\n\
   --help                       Show this message.\n\
   --mnmp-port                  Specify MNMP port of server, default is 41017.\n\
   --netflow-addr               IPv4 address to accept Netflow on.\n\
   --netflow-port               UDP port to accept Netflow on.\n\
   --no-compression             Do not compress flow messages.\n\
   --syslog			Log messages to syslogd.\n\
   --trusted-certs <dir>        Path to directory containing trusted certificates.\n\
   --quiet			Only log errors.\n\
  \n", progname);
}

int main(int argc, char ** argv)
{
  Logging::level = Logging::LEVEL_INFO;

  bool do_netflow_relay = false;

  for (int idx=1; idx < argc; idx++)
  {
    std::string arg = argv[idx];
    if (arg == "--id") {
     std::string::size_type sz = 0;
      MNMP_ID = std::stoull(argv[++idx], &sz, 0);
      DEBUGF("MNMP id assigned to %llu", (long long unsigned)MNMP_ID);
    } else if (arg == "--netprofiler") {
      MNMP_SERVER = argv[++idx];
      DEBUGF("NetProfiler address set to %s", MNMP_SERVER.c_str());
    } else if (arg == "--no-compression") {
      MNMP_COMPRESSION = MNMPMessage::COMPRESSION_NONE;
      DEBUGF("not using LZ4 for flows compression");
    } else if (arg == "--certificate") {
      SSL_CERTIFICATE = argv[++idx];
      DEBUGF("using SSL certificate %s", SSL_CERTIFICATE.c_str());
    } else if (arg == "--trusted-certs") {
      SSL_TRUSTED_DIR = argv[++idx];
      DEBUGF("SSL trusted certificate directory is %s", SSL_CERTIFICATE.c_str());
    } else if (arg == "--mnmp-port") {
      MNMP_SSL_PORT = atoi(argv[++idx]);
      DEBUGF("using port %u for MNMP connection", MNMP_SSL_PORT);
    } else if (arg == "--netflow-relay") {
      do_netflow_relay = true;
      DEBUGF("relaying netflow task enabled");
    } else if (arg == "--netflow-addr") {
      NETFLOW_ADDR = argv[++idx];
      DEBUGF("relaying netflow from addr %s", NETFLOW_ADDR.c_str());
    } else if (arg == "--netflow-port") {
      NETFLOW_PORT = atoi(argv[++idx]);
      DEBUGF("relaying netflow from port %u", NETFLOW_PORT);
    } else if (arg == "--syslog") {
      std::ostringstream sa;
      std::string path = argv[0];
      sa << path.substr(path.find_last_of("/\\") + 1) 
         << "[" << ::getpid() << "]";
      SYSLOG_NAME = sa.str();
      DEBUGF("enabling syslog, %s", SYSLOG_NAME.c_str());
      Logging::enable_syslog(SYSLOG_NAME.c_str());
    } else if (arg == "--debug") {
      Logging::level = Logging::LEVEL_DEBUG;
    } else if (arg == "--debug2") {
      Logging::level = Logging::LEVEL_DEBUG2;
    } else if (arg == "--debug3") {
      Logging::level = Logging::LEVEL_DEBUG3;
    } else if (arg == "--quiet") {
      Logging::level = Logging::LEVEL_ERROR;
    } else if (arg == "-h" || arg == "--help") {
      print_usage(argv[0]);
      exit(0);
    } else {
      print_usage(argv[0]);
      exit(1);
    }
  }

  if (MNMP_ID == 0 || MNMP_SERVER.empty()) {
    print_usage(argv[0]);
    exit(1);
  }

  if (do_netflow_relay)
    do_netflow_relay_task();

  return 0;
}
