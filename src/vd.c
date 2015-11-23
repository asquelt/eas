#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/utsname.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rand.h"

#include "config.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
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
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include "client_id.h"
#include "ssl.h"
#include "socket.h"
#include "sig.h"
#include "servconf.h"
#include "log.h"
#include "random.h"
#include "sql.h"
#include "vd.h"

#include "../sqlite/sqlite3.h"

void print_version(struct ServerOption *option, const char *prog)
{
	int i = -1;
	struct utsname u;

	fprintf(stdout, "Enterprise Audit Shell version information:\n");
	fprintf(stdout, " + %.63s (%.63s) version %.31s\n", basename(prog), PACKAGE_NAME, PACKAGE_VERSION);
	fprintf(stdout, " + SHA1 = %.255s\n", create_SHA1(prog, 0, 0, 0, 0, 0));
	fprintf(stdout, "\nOption information:\n");
	fprintf(stdout, " + Port = %i\n", option->port);

	if(option->listenaddress)
		fprintf(stdout, " + ListenAddress = %.31s\n", option->listenaddress);
	if(option->pidfile)
		fprintf(stdout, " + PidFile = %.127s\n", option->pidfile);

	switch(option->level)
	{
		case eINFO:
			fprintf(stdout, " + LogLevel = INFO\n");
			break;
		case eDEBUG1:
			fprintf(stdout, " + LogLevel = DEBUG1\n");
			break;
		case eDEBUG2:
			fprintf(stdout, " + LogLevel = DEBUG2\n");
			break;
		case eDEBUG3:
			fprintf(stdout, " + LogLevel = DEBUG3\n");
			break;
		default:
			fprintf(stdout, " + LogLevel = UNKNOWN\n");
			break;
	}

	switch(option->facility)
	{
		case LOG_KERN:
			fprintf(stdout, " + SyslogFacility = LOG_KERN\n");
			break;
		case LOG_USER:
			fprintf(stdout, " + SyslogFacility = LOG_USER\n");
			break;
		case LOG_MAIL:
			fprintf(stdout, " + SyslogFacility = LOG_MAIL\n");
			break;
		case LOG_DAEMON:
			fprintf(stdout, " + SyslogFacility = LOG_DAEMON\n");
			break;
		case LOG_AUTH:
			fprintf(stdout, " + SyslogFacility = LOG_AUTH\n");
			break;
		case LOG_LPR:
			fprintf(stdout, " + SyslogFacility = LOG_LPR\n");
			break;
		case LOG_NEWS:
			fprintf(stdout, " + SyslogFacility = LOG_NEWS\n");
			break;
		case LOG_UUCP:
			fprintf(stdout, " + SyslogFacility = LOG_UUCP\n");
			break;
		case LOG_CRON:
			fprintf(stdout, " + SyslogFacility = LOG_CRON\n");
			break;
		case LOG_LOCAL0:
			fprintf(stdout, " + SyslogFacility = LOG_LOCAL0\n");
			break;
		case LOG_LOCAL1:
			fprintf(stdout, " + SyslogFacility = LOG_LOCAL1\n");
			break;
		case LOG_LOCAL2:
			fprintf(stdout, " + SyslogFacility = LOG_LOCAL2\n");
			break;
		case LOG_LOCAL3:
			fprintf(stdout, " + SyslogFacility = LOG_LOCAL3\n");
			break;
		case LOG_LOCAL4:
			fprintf(stdout, " + SyslogFacility = LOG_LOCAL4\n");
			break;
		case LOG_LOCAL5:
			fprintf(stdout, " + SyslogFacility = LOG_LOCAL5\n");
			break;
		case LOG_LOCAL6:
			fprintf(stdout, " + SyslogFacility = LOG_LOCAL6\n");
			break;
		case LOG_LOCAL7:
			fprintf(stdout, " + SyslogFacility = LOG_LOCAL7\n");
			break;
		default:
			fprintf(stdout, " + Facility = UNKNOWN\n");
			break;
	}

	switch(option->priority)
	{
		case LOG_EMERG:
			fprintf(stdout, " + SyslogPriority = LOG_EMERG\n");
			break;
		case LOG_ALERT:
			fprintf(stdout, " + SyslogPriority = LOG_ALERT\n");
			break;
		case LOG_CRIT:
			fprintf(stdout, " + SyslogPriority = LOG_CRIT\n");
			break;
		case LOG_ERR:
			fprintf(stdout, " + SyslogPriority = LOG_ERR\n");
			break;
		case LOG_WARNING:
			fprintf(stdout, " + SyslogPriority = LOG_WARNING\n");
			break;
		case LOG_NOTICE:
			fprintf(stdout, " + SyslogPriority = LOG_NOTICE\n");
			break;
		case LOG_INFO:
			fprintf(stdout, " + SyslogPriority = LOG_INFO\n");
			break;
		case LOG_DEBUG:
			fprintf(stdout, " + SyslogPriority = LOG_DEBUG\n");
			break;
		default:
			fprintf(stdout, " + SyslogPriority = UNKNOWN\n");
			break;
	}

	if(option->cipher)
		fprintf(stdout, " + Cipher = %.127s\n", option->cipher);

	switch(option->eash_method)
	{
		case TLSv1:
			fprintf(stdout, " + Method = TLSv1\n");
			break;
		case SSLv2:
			fprintf(stdout, " + Method = SSLv2\n");
			break;
		case SSLv3:
			fprintf(stdout, " + Method = SSLv3\n");
			break;
		case SSLv23:
			fprintf(stdout, " + Method = SSLv23\n");
			break;
		default:
			fprintf(stdout, " + Method = UNKNOWN\n");
			break;
	}

	if(option->pemfile)
		fprintf(stdout, " + PrivateKey = %.255s\n", option->pemfile);

	for(i = 0; option->cafiles[i] != NULL; i++)
		fprintf(stdout, " + CertificateAuthority = %.255s\n", option->cafiles[i]);

	if(option->randomfile)
		fprintf(stdout, " + RandomFile = %.255s\n", option->randomfile);

	if(option->egdfile)
		fprintf(stdout, " + EGDFile = %.255s\n", option->egdfile);

	if(option->sessiondirectory)
		fprintf(stdout, " + SessionDirectory = %.255s\n", option->sessiondirectory);

	fprintf(stdout, " + User = %i\n", option->uid);
	fprintf(stdout, " + Group = %i\n", option->gid);

	if(option->keepalive)
		fprintf(stdout, " + KeepAlive = yes\n");
	else
		fprintf(stdout, " + KeepAlive = no\n");

	if(option->idletimeout > 0)
		fprintf(stdout, " + IdleTimeout = %i\n", option->idletimeout);
	else
		fprintf(stdout, " + IdleTimeout = disabled\n");

	fprintf(stdout, "\nLibrary information:\n");
	fprintf(stdout, " + OpenSSL version 0x%lx\n", OPENSSL_VERSION_NUMBER);
	fprintf(stdout, " + SQLite version %.31s\n", SQLITE_VERSION);

	if(uname(&u) < 0)
	{
		fprintf(stderr, "uname: %.100s (%i)\n", strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "\nSystem information:\n");
	fprintf(stdout, " + Processor = %.255s\n", u.machine);
	fprintf(stdout, " + Machine = %.255s\n", u.nodename);
	fprintf(stdout, " + System = %.255s %.255s (%.255s)\n", u.sysname, u.release, u.version);

	return;
}
