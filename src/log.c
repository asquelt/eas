#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rand.h"

#include "config.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif

#include "sig.h"
#include "servconf.h"

extern struct ServerOption option;

void do_log(int level, const char *fmt, va_list args)
{
	int facility = option.facility;
	int priority = option.priority;
	char *prefix = (char *) 0;
	char fmtbuf[1024];
	char msgbuf[1024];

	/* only log what's appropiate defined from easd_config LogLevel */
	if(level > option.level)
		return;

	switch(level)
	{
		case eINFO:
			break;
		case eDEBUG1:
			prefix = "debug1";
			priority = LOG_DEBUG;
			break;
		case eDEBUG2:
			prefix = "debug2";
			priority = LOG_DEBUG;
			break;
		case eDEBUG3:
			prefix = "debug3";
			priority = LOG_DEBUG;
			break;
		case eERROR:
			prefix = "error";
			priority = LOG_ERR;
			break;
		default:
			prefix = "internal error";
			priority = LOG_CRIT;
			break;
	}

	if(prefix != (char *) 0)
	{
		if(level > eINFO)
			snprintf(fmtbuf, sizeof(fmtbuf), "%s: (%i) %s", prefix, getpid(), fmt);
		else
			snprintf(fmtbuf, sizeof(fmtbuf), "%s: %s", prefix, fmt);

		vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
	}
	else
	{
		vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
	}

	openlog("easd", LOG_PID, facility);
	syslog(priority, "%.500s", msgbuf);
	closelog();
}

void s_log(int level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(level, fmt, args);
	va_end(args);
}
