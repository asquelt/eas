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

char *basename(const char *str)
{
	char *p;

	if(str == (const char *) 0)
		return (char *) 0;

	p = strrchr(str, '/');

	if(p == (char *) 0)
		return (char *) str;
	else if(p + 1 != (char *) 0)
		return p + 1;
	else
		return (char *) str;
}

int validshell(const char *shell)
{
        FILE *fp;
        char buffer[BUFSIZ];

	if((fp = fopen("/etc/shells", "r")) == (FILE *) 0)
	{
		/* /etc/shells doesn't exist - use /bin/sh,  /bin/csh */
		const char *okshells[] = { "/sbin/sh", "/bin/sh", "/bin/csh", "/usr/bin/ksh", "/bin/ksh", "/bin/bash", 0 };
		register int i = 0;

		s_log(eINFO, "warning: /etc/shells: %.100s (%i)", strerror(errno), errno);

		for(i = 0; okshells[i]; i++)
			if(!strcmp(okshells[i], shell))
				return(0);

		return(-1);
	}

	memset(buffer, '\0', sizeof(buffer));

	while(fgets(buffer, sizeof(buffer) - 1, fp))
	{
		if(buffer[strlen(buffer)-1] == '\n')
			buffer[strlen(buffer)-1] = '\0';

		if(!strcmp(buffer, shell))
		{
			fclose(fp);
			return(0);
		}
	}

	fclose(fp);
	return(-1);
}
