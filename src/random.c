#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rand.h"

#include "config.h"

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "servconf.h"
#include "client_id.h"
#include "ssl.h"
#include "socket.h"
#include "sig.h"

/* function declarations */
extern struct ServerOption option;

int myrand(void)
{
        unsigned int seed;
        FILE *f = (FILE *) 0;

        if((f = fopen(option.randomfile, "r")) != (FILE *) 0)
        {
                fread(&seed, sizeof(seed), 1, f);
                fclose(f); /* I forgot to close f once and I hit the open files limit (errno 24) */
        }
        else if((f = fopen("/dev/urandom", "r")) != (FILE *) 0)
        {
                fread(&seed, sizeof(seed), 1, f);
                fclose(f); /* I forgot to close f once and I hit the open files limit (errno 24) */
        }
        else /* do it our fucking selves I guess (you'd be surprised) */
        {
                struct timeval tv;

                gettimeofday(&tv, (struct timezone *) 0);
                /* prime numbers */
                seed = (tv.tv_sec % 10000) * 523 + tv.tv_usec * 13 + (getpid() % 1000) * 983;
                srand(seed);
                seed = rand();
        }

        return seed;
}

char *rand2str(size_t len)
{
        static char buf[BUFSIZ];
        char *ptr = buf;
        char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        int i;

        if(len > BUFSIZ - 1)
                len = BUFSIZ -1;

        memset(ptr, '\0', BUFSIZ);

        if (len < 0)
                return (char *) 0;
        if (len >= BUFSIZ)
                len = BUFSIZ - 1;

        for (i = 0; i < len; i++)
        {
                int j = (myrand() & 0xffff) % strlen(alphabet);

                ptr[i] = alphabet[j];
        }

        return buf;
}
