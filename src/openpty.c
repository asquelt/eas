#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "config.h"

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

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_SYS_TERMIO_H
#include <sys/termio.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif

#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#if !defined(HAVE_OPENPTY)
/* in case we're on a system that doesn't have its own openpty() */
int openpty(int *amaster, int *aslave, char *name, struct termios *termp, struct winsize *winp)
{
	if((*amaster = open("/dev/ptmx", O_RDWR)) < 0)
	{
		if((*amaster = open("/dev/ptc", O_RDWR)) < 0)
		{
			fprintf(stderr, "Cannot open master pty.\n");
			return(EXIT_FAILURE);
		}
	}

	unlockpt(*amaster);
	grantpt(*amaster);

	if(name)
		strcpy(name, ptsname(*amaster));
	if(termp)
		tcsetattr(*aslave, TCSAFLUSH, termp);
	if(winp)
		ioctl(*aslave, TIOCSWINSZ, (char *) winp);

	if(chown(name, getuid(), getgid()) < 0)
	{
		fprintf(stderr, "chown(%.127s, %i, %i): %.100s (%i)\n", name, getuid(), getgid(), strerror(errno), errno);
		return(-1);
	}

	if(chmod(name, S_IRUSR | S_IWUSR | S_IWGRP) < 0)
	{
		fprintf(stderr, "chmod(%.127s, %o): %.100s (%i)\n", name, S_IRUSR | S_IWUSR | S_IWGRP, strerror(errno), errno);
		return(-1);
	}

	if((*aslave = open(name, O_RDWR)) < 0)
	{
		fprintf(stderr, "open(%.100s): %100s (%i)\n", name, strerror(errno), errno);
		return(-1);
	}

#ifdef I_LIST
	if(ioctl(*aslave, I_LIST, NULL) > 0)
	{
		if(ioctl(*aslave, I_FIND, "ldterm") != 1 && ioctl(*aslave, I_FIND, "ldtty") != 1)
		{
			ioctl(*aslave, I_PUSH, "ptem");
			ioctl(*aslave, I_PUSH, "ldterm");
		}
	}
#endif

	return(0);
}
#endif
