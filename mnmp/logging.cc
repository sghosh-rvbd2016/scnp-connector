#include "logging.hh"

unsigned Logging::level = LEVEL_INFO;
bool Logging::use_syslog = false;

const char *
Logging::level_str(int level)
{
  switch(level)
  {
    case LEVEL_INFO:
      return "INFO";
    case LEVEL_WARNING:
      return "WARNING";
    case LEVEL_NOTICE:
      return "NOTICE";
    case LEVEL_DEBUG:
      return "DEBUG";
    case LEVEL_DEBUG2:
      return "DEBUG2";
    case LEVEL_DEBUG3:
      return "DEBUG3";
    case LEVEL_FATAL:
      return "FATAL";
    case LEVEL_ALERT:
      return "ALERT";
    case LEVEL_EMERG:
      return "EMERGENCY";
    case LEVEL_ERROR:
      return "ERROR";
    default:
      return "UNDEFINED";
  }
}

void
Logging::enable_syslog(const char *name)
{
  Logging::use_syslog = true;
  setlogmask(LOG_UPTO (Logging::level));
  openlog(name, LOG_NDELAY, LOG_LOCAL0);
}
