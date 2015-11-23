#include "config.h"

#ifndef _DEFINES_H
#define _DEFINES_H

#ifndef SHUT_RDWR
enum { SHUT_RD = 0, SHUT_WR, SHUT_RDWR };
#define SHUT_RD SHUT_RD
#define SHUT_WR SHUT_WR
#define SHUT_RDWR SHUT_RDWR
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

#ifndef HAVE_SIG_ATOMIC_T
typedef int sig_atomic_t;
#endif

#ifndef HAVE_PID_T
typedef int pid_t;
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#ifndef _PATH_SHELLS
#define _PATH_SHELLS "/etc/shells"
#endif

#ifndef _PATH_STDPATH
#define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#endif

#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL "/dev/null"
#endif

#endif
