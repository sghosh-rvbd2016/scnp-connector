#ifndef LOGGING_HH
#define LOGGING_HH

#include <syslog.h>
#include <stdio.h>
#include <cstdarg>
#include <stdlib.h>
#include <ctime>

class Logging
{
public:

  enum { LEVEL_EMERG = LOG_EMERG,
         LEVEL_ALERT = LOG_ALERT,
         LEVEL_FATAL = LOG_CRIT,
         LEVEL_ERROR = LOG_ERR,
         LEVEL_WARNING = LOG_WARNING,
         LEVEL_NOTICE = LOG_NOTICE,
         LEVEL_INFO = LOG_INFO,
         LEVEL_DEBUG = LOG_DEBUG,
         LEVEL_DEBUG2, LEVEL_DEBUG3 };

  static unsigned level;
  static bool use_syslog;
  static void enable_syslog(const char *procname);
  static const char *level_str(int level);
};

#define INFOF(format, args...) if(Logging::level >= Logging::LEVEL_INFO) \
                                 LOG_MESSAGE(Logging::LEVEL_INFO, format, ## args)
#define WARNINGF(format, args...) if(Logging::level >= Logging::LEVEL_WARNING) \
                                    LOG_MESSAGE(Logging::LEVEL_WARNING, format, ## args)
#define DEBUGF(format, args...) if(Logging::level >= Logging::LEVEL_DEBUG) \
                                  LOG_MESSAGE(Logging::LEVEL_DEBUG, format, ## args)
#define DEBUG2F(format, args...) if(Logging::level >= Logging::LEVEL_DEBUG2) \
                                   LOG_MESSAGE(Logging::LEVEL_DEBUG2, format, ## args)
#define DEBUG3F(format, args...) if(Logging::level >= Logging::LEVEL_DEBUG3) \
                                   LOG_MESSAGE(Logging::LEVEL_DEBUG3, format, ## args)
#define ERRORF(format, args...) if(Logging::level >= Logging::LEVEL_ERROR) \
                                  LOG_MESSAGE(Logging::LEVEL_ERROR, format, ## args)
#define NOTICEF(format, args...) if(Logging::level >= Logging::LEVEL_NOTICE) \
                                  LOG_MESSAGE(Logging::LEVEL_NOTICE, format, ## args)

#define LOG_MESSAGE(level, format, args...) \
  do { \
    if (Logging::use_syslog && level <= Logging::LEVEL_DEBUG) { \
      syslog(level, format, ## args); \
    } else { \
      char buffer[32]; \
      time_t now = time(0); \
      std::tm *ptm = std::localtime(&now); \
      strftime(buffer, 32, "%FT%T%z", ptm); \
      printf("%s [%s] ", buffer, Logging::level_str(level)); \
      printf(format, ## args); \
      printf("\n"); \
    } \
  } while(0)

#define FATALF(format, args...) \
  do { \
    LOG_MESSAGE(Logging::LEVEL_FATAL, format, ## args); \
    exit(1); \
  } while(0)

/*
void INFOF(const char* format, ...);
void WARNINGF(const char* format, ...);
void DEBUGF(const char* format, ...);
void DEBUG2F(const char* format, ...);
void DEBUG3F(const char* format, ...);
void NOTICE(const char* format, ...);
void ERRORF(const char* format, ...);
void FATALF(const char* format, ...);
*/

#define AT_MOST_ONCE_IN_INTERVAL(interval, task)        \
 do {                                                   \
     static time_t __last_time = 0;                     \
     time_t __now = std::time(NULL);             \
     if (__now - __last_time >= interval) {     \
       __last_time = __now;                     \
       task;                                            \
     }                                                  \
  } while (0)

#define AT_MOST_ONCE_A_SECOND(what) AT_MOST_ONCE_IN_INTERVAL(1, what)
#define AT_MOST_ONCE_A_MINUTE(what) AT_MOST_ONCE_IN_INTERVAL(60, what)

#define AT_MOST_ONCE_IN_INTERVAL_FOR_EACH(num, index, interval, task)   \
 do {                                                   \
     static time_t __last_time[num];                    \
     time_t __now = std::time(NULL);             \
     if (__now - __last_time[index] >= interval) {      \
       __last_time[index] = __now;                      \
       task;                                            \
     }                                                  \
  } while (0)

#define AT_MOST_ONCE_A_SECOND_FOR_EACH(num, index, what) AT_MOST_ONCE_IN_INTERVAL_FOR_EACH(num, index, 1, what)
#define AT_MOST_ONCE_A_MINUTE_FOR_EACH(num, index, what) AT_MOST_ONCE_IN_INTERVAL_FOR_EACH(num, index, 60, what)

#endif
