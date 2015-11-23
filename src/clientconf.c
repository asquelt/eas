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

#include "clientconf.h"
#include "client_id.h"
#include "ssl.h"
#include "socket.h"
#include "sig.h"

extern struct ClientOption option;

typedef enum
{
	eBadOption,
	ePort,
	eLogServer,
	eDefaultShell,
	eSyslogFacility,
	eSyslogPriority,
	eLogLevel,
	eCipher,
	eMethod,
	ePrivateKey,
	eCertificateAuthority,
	eRandomFile,
	eTCPTimeout,
	eBannerFile,
	eBannerPause,
	eEGDFile
} ConfigKey;

static struct
{
	const char *name;
	ConfigKey key;
} keywords[] =
{
	{ "port", ePort },
	{ "logserver", eLogServer },
	{ "defaultshell", eDefaultShell },
	{ "syslogfacility", eSyslogFacility },
	{ "syslogpriority", eSyslogPriority },
	{ "loglevel", eLogLevel },
	{ "cipher", eCipher },
	{ "method", eMethod },
	{ "privatekey", ePrivateKey },
	{ "certificateauthority", eCertificateAuthority },
	{ "ca", eCertificateAuthority },
	{ "crl", eCertificateAuthority },
	{ "certificaterevocationlist", eCertificateAuthority },
	{ "randomfile", eRandomFile },
	{ "tcptimeout", eTCPTimeout },
	{ "egdfile", eEGDFile },
	{ "bannerfile", eBannerFile },
	{ "bannerpause", eBannerPause },
	{ NULL, eBadOption }
};

#if 0
static int is_string(const char *str)
{
	while(*str)
		if(isalpha(*str++))
			return(-1);

	return(0);
}
#endif

int verify_file(const char *file, int line, const char *ptr)
{
        struct stat s;

        if(stat(ptr, &s) < 0)
        {
                fprintf(stderr, "[%.100s, line %i]: %.100s: %.100s (%i)\n", file, line, ptr, strerror(errno), errno);
                return(-1);
        }
        else
                return(0);
}

static ConfigKey get_token(const char *key)
{
	register int i;

	for(i = 0; keywords[i].name; i++)
		if(!strcasecmp(key, keywords[i].name))
			return keywords[i].key;

	return eBadOption;
}

void init_options(void)
{
	if((option.cafiles = malloc(sizeof(char *) * 1)) == (char **) 0)
	{
		fprintf(stderr, "malloc: %.100s (%i)\n", strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	option.cafiles[0] = 0;

	if((option.log_servers = malloc(sizeof(char *) * 1)) == (char **) 0)
	{
		fprintf(stderr, "malloc: %.100s (%i)\n", strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	option.log_servers[0] = 0;

	/* default options */
	option.port = 5554;
	option.banner_pause = -1;
	option.facility = LOG_AUTH;
	option.priority = LOG_INFO;
	option.method = SSLv3_client_method();
	option.pemfile = "/etc/eas/certs/client.pem";
	option.egdfile = 0;
	option.randomfile = 0;
	option.cipher = "HIGH:MEDIUM";
	option.method = 0;
	option.default_shell = "/bin/sh";
	option.banner = 0;
	option.tcptimeout = 2;

	return;
}

int load_config(const char *file)
{
	FILE *f;
	char line[BUFSIZ];
	int ln = 1;

	if(file == (const char *) 0)
	{
		fprintf(stderr, "please supply a configuration file.\n");
		fprintf(stderr, "EASH_CONFIG = %.100s\n", EASH_CONFIG);
		return(-1);
	}

	if((f = fopen(file, "r")) == (FILE *) 0)
	{
		fprintf(stderr, "%.100s: %.100s (%i)\n", file, strerror(errno), errno);
		return(-1);
	}

	for(ln = 1; fgets(line, sizeof(line), f); ln++)
	{
		char key[1024];
		char val[1024];
		char *ptr;
		int x = 0;

		ptr = line;

		/* skip initial white space */
		while(isspace(*ptr))
			ptr++;

		if(strlen(ptr) <= 0)
			continue;

		if(*ptr == '#' || *ptr == '\n' || *ptr == '\r')
			continue;

		switch(sscanf(ptr, "%1000[^ \t]%1000s\n", (char *) &key, (char *) &val))
		{
			/* found both key and value pairs */
			case 2:
				switch(get_token(key))
				{
					case ePort:
						option.port = atol(val);

						if(option.port < 1 || option.port > 65536)
						{
							fprintf(stderr, "[%.100s, line %i]: port %i out of range.\n", file, ln, option.port);
							return(-1);
						}
						break;
					case eBannerPause:
						option.banner_pause = atol(val);

						if(option.banner_pause > 65536)
						{
							fprintf(stderr, "[%.100s, line %i]: BannerPause %i out of range.\n", file, ln, option.port);
							return(-1);
						}
						break;
					case eTCPTimeout:
						option.tcptimeout = atol(val);

						if(option.tcptimeout < 1 || option.tcptimeout > 65536)
						{
							fprintf(stderr, "[%.100s, line %i]: timeout %i out of range.\n", file, ln, option.tcptimeout);
							return(-1);
						}
						break;
					case eLogLevel:
						if(!strcasecmp(val, "info"))
							option.level = eINFO;
						else if(!strcasecmp(val, "debug1"))
							option.level = eDEBUG1;
						else if(!strcasecmp(val, "debug2"))
							option.level = eDEBUG2;
						else if(!strcasecmp(val, "debug3"))
							option.level = eDEBUG3;
						else
						{
							fprintf(stderr, "[%.100s, line %i]: invalid log level.\n", file, ln);
							return(-1);
						}
						break;
					case eSyslogFacility:
						if(!strcasecmp(val, "log_kern"))
							option.facility = LOG_KERN;
						else if(!strcasecmp(val, "log_user"))
							option.facility = LOG_USER;
						else if(!strcasecmp(val, "log_mail"))
							option.facility = LOG_MAIL;
						else if(!strcasecmp(val, "log_daemon"))
							option.facility = LOG_DAEMON;
						else if(!strcasecmp(val, "log_auth"))
							option.facility = LOG_AUTH;
						else if(!strcasecmp(val, "log_lpr"))
							option.facility = LOG_LPR;
						else if(!strcasecmp(val, "log_news"))
							option.facility = LOG_NEWS;
						else if(!strcasecmp(val, "log_uucp"))
							option.facility = LOG_UUCP;
						else if(!strcasecmp(val, "log_cron"))
							option.facility = LOG_CRON;
						else if(!strcasecmp(val, "log_local0"))
							option.facility = LOG_LOCAL0;
						else if(!strcasecmp(val, "log_local1"))
							option.facility = LOG_LOCAL1;
						else if(!strcasecmp(val, "log_local2"))
							option.facility = LOG_LOCAL2;
						else if(!strcasecmp(val, "log_local3"))
							option.facility = LOG_LOCAL3;
						else if(!strcasecmp(val, "log_local4"))
							option.facility = LOG_LOCAL4;
						else if(!strcasecmp(val, "log_local5"))
							option.facility = LOG_LOCAL5;
						else if(!strcasecmp(val, "log_local6"))
							option.facility = LOG_LOCAL6;
						else if(!strcasecmp(val, "log_local7"))
							option.facility = LOG_LOCAL7;
						else
						{
							fprintf(stderr, "[%.100s, line %i]: invalid syslog facility.\n", file, ln);
							return(-1);
						}
						break;
					case eSyslogPriority:
						if(!strcasecmp(val, "log_emerg"))
							option.priority = LOG_EMERG;
						else if(!strcasecmp(val, "log_alert"))
							option.priority = LOG_ALERT;
						else if(!strcasecmp(val, "log_crit"))
							option.priority = LOG_CRIT;
						else if(!strcasecmp(val, "log_err"))
							option.priority = LOG_ERR;
						else if(!strcasecmp(val, "log_warning"))
							option.priority = LOG_WARNING;
						else if(!strcasecmp(val, "log_notice"))
							option.priority = LOG_NOTICE;
						else if(!strcasecmp(val, "log_info"))
							option.priority = LOG_INFO;
						else if(!strcasecmp(val, "log_debug"))
							option.priority = LOG_DEBUG;
						else
						{
							fprintf(stderr, "[%.100s, line %i]: invalid syslog priority.\n", file, ln);
							return(-1);
						}
						break;
					case eBannerFile:
						option.banner = strdup(val);
						break;
					case eCipher:
						option.cipher = strdup(val);
						break;
					case eDefaultShell:
						option.default_shell = strdup(val);
						if(verify_file(file, ln, option.default_shell) < 0)
							return(-1);
						break;
					case eMethod:
						if(!strcasecmp(val, "tlsv1"))
						{
							option.eash_method = TLSv1;
							option.method = TLSv1_client_method();
						}
						else if(!strcasecmp(val, "sslv2"))
						{
							option.eash_method = SSLv2;
							option.method = SSLv2_client_method();
						}
						else if(!strcasecmp(val, "sslv3"))
						{
							option.eash_method = SSLv3;
							option.method = SSLv3_client_method();
						}
						else if(!strcasecmp(val, "sslv23"))
						{
							option.eash_method = SSLv23;
							option.method = SSLv23_client_method();
						}
						else
						{
							fprintf(stderr, "[%.100s, line %i]: invalid SSL method.\n", file, ln);
							return(-1);
						}
						break;
					case ePrivateKey:
						option.pemfile = strdup(val);
						if(verify_file(file, ln, option.pemfile) < 0)
							return(-1);
						break;
					case eRandomFile:
						option.randomfile = strdup(val);
						if(verify_file(file, ln, option.randomfile) < 0)
							return(-1);
						break;
					case eEGDFile:
						option.egdfile = strdup(val);
						if(verify_file(file, ln, option.egdfile) < 0)
							return(-1);
						break;
					case eCertificateAuthority:
						x = 0;

						while(option.cafiles[x] != NULL)
							x++;

						if(!(option.cafiles = realloc(option.cafiles, sizeof(char *) * (x + 2))))
						{
							fprintf(stderr, "realloc: %.100s (%i)\n", strerror(errno), errno);
							return(-1);
						}

						if(!(option.cafiles[x] = strdup(val)))
						{
							fprintf(stderr, "strdup: %.100s (%i)\n", strerror(errno), errno);
							return(-1);
						}

						option.cafiles[x + 1] = 0;
						break;
					case eLogServer:
						x = 0;

						while(option.log_servers[x] != NULL)
							x++;

						if(!(option.log_servers = realloc(option.log_servers, sizeof(char *) * (x + 2))))
						{
							fprintf(stderr, "realloc: %.100s (%i)\n", strerror(errno), errno);
							return(-1);
						}

						if(!(option.log_servers[x] = strdup(val)))
						{
							fprintf(stderr, "strdup: %.100s (%i)\n", strerror(errno), errno);
							return(-1);
						}

						option.log_servers[x + 1] = 0;
						break;
					case eBadOption:
						fprintf(stderr, "[%.100s, line %i]: bad configuration option: %.63s\n", file, ln, key);
						return(-1);
						break;
				}
				break;
			case 1:
				if(key[strlen(key)-1] == '\n')
					key[strlen(key)-1] = '\0';

				switch(get_token(key))
				{
					case eBadOption:
						fprintf(stderr, "[%.100s, line %i]: bad configuration option: %.63s\n", file, ln, key);
						return(-1);
						break;
					default:
						fprintf(stderr, "[%.100s, line %i]: missing arguement.\n", file, ln);
						return(-1);
						break;
				}
				break;
			default:
				fprintf(stderr, "[%.100s, line %i]: invalid syntax.\n", file, ln);
				return(-1);
				break;
		}
	}

	fclose(f);

	return(0);
}
