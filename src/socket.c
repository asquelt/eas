#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
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
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include "client_id.h"
#include "ssl.h"
#include "socket.h"
#include "servconf.h"
#include "log.h"
#include "defines.h"

extern struct ServerOption option;

int set_reuseaddr(int sock, int val)
{
	s_log(eDEBUG3, "setsockopt(%i, SO_REUSEADDR, %i)", sock, val);

	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof (val)) < 0)
	{
		s_log(eERROR, "setsockopt: %.100s (%i)\n", strerror(errno), errno);
		return(-1);
	}

	if(option.keepalive)
	{
		s_log(eDEBUG1, "setting listen socket to SO_KEEPALIVE");
		s_log(eDEBUG3, "setsockopt(%i, SO_KEEPALIVE, %i)", sock, val);
		if(setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof (val)) < 0)
		{
			s_log(eERROR, "setsockopt: %.100s (%i)\n", strerror(errno), errno);
			return(-1);
		}
	}

	return (0);
}

int listen_sock(unsigned short int port)
{
	int sock;

	if(port <= 0)
	{
		s_log(eERROR, "port %d out of range. (1-65536)\n", port);
		return(-1);
	}

	if((sock = bind_sock (port)) < 0)
		return(-1);

	s_log(eDEBUG3, "listen(%i, 500)", sock);
	if(listen(sock, 500) < 0)
	{
		s_log(eERROR, "listen: %.100s (%i)\n", strerror(errno), errno);
		return(-1);
	}

	return (sock);
}

int bind_sock(unsigned short int port)
{
	int                     sock;
	struct sockaddr_in      sin;

	if((sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		s_log(eERROR, "socket: %.100s (%i)\n", strerror(errno), errno);
		return(-1);

	}

	s_log(eDEBUG3, "socket() = %i", sock);

	set_reuseaddr(sock, 1);

	sin.sin_family          = AF_INET;
	sin.sin_port            = htons(port);
	sin.sin_addr.s_addr     = INADDR_ANY;

	if(bind(sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
	{
		s_log(eERROR, "bind: %.100s (%i)\n", strerror(errno), errno);
		return(-1);
	}

	s_log(eDEBUG3, "bind(%i)", sock);

	return(sock);
}

int wait_for_connect(int sock, struct client_info *c)
{
        int fd;
	socklen_t len = sizeof (struct sockaddr_in);
        struct sockaddr_in sin;

	s_log(eDEBUG2, "accept(%i)", sock);
	if((fd = accept (sock, (struct sockaddr *) &sin, &len)) == -1)
	{
		if(errno != EINTR && errno != EWOULDBLOCK)
		{
			s_log(eERROR, "accept: %.100s (%i)\n", strerror(errno), errno);
			return(-1);
		}
		/* this type of error is OK */
		return (-2);
	}
	s_log(eDEBUG1, "accept(%i) == %i", sock, fd);

	c->cid.port = ntohs(sin.sin_port);
	strncpy(c->cid.ip, inet_ntoa(sin.sin_addr), sizeof(c->cid.ip));
	snprintf(c->where, sizeof(c->where) - 1, "%s:%d", c->cid.ip, c->cid.port);
	s_log(eDEBUG1, "connection received from %s", c->where);

	return (fd);
}

int connect_tcp(struct in_addr *ip, unsigned short port, unsigned short sport, int timeout, int print)
{
	int sock;
	int c;
	int err;
	int l;
	int oldflags = -1;
	struct sockaddr_in s_in;
	struct timeval tv;
	fd_set fds;

	if(sport)
	{
		if((sock = bind_sock (sport)) < 0)
			return(-1);
	}
	else
	{
		if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			fprintf(stderr, "socket: %.100s (%i)\n", strerror(errno), errno);
			return(-1);
		}
	}

	s_in.sin_family = AF_INET;
	s_in.sin_port = htons(port);
	s_in.sin_addr.s_addr = ip->s_addr;

	if((oldflags = set_nonblocking_mode(sock)) < 0)
		return(-1);

	if((c = connect(sock, (struct sockaddr *) &s_in, sizeof(s_in))) == -1)
	{
		if(errno != EINPROGRESS && errno != EAGAIN)
		{
			close(sock);
			fprintf(stderr, "%.100s (%i)\n", strerror(errno), errno);
			return(-1);
		}
	}
	else if(c == 0)
	{
		if(print)
			fprintf(stderr, "connected.\n");

		if(unset_nonblocking_mode(sock, oldflags) < 0)
			return(-1);

		return (sock);
	}

	/* Everyone else is OK, but AIX will error out if you don't ZERO the fd set */
	/* AIX isn't "odd" - it's just that you should always zero out all variables in C */
	/* People can complain about AIX all they want - it's just that they're lazy or poor programmers */
	FD_ZERO(&fds);
	FD_SET(sock, &fds);

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	l = sizeof(err);

	if((c = select(sock + 1, &fds, &fds, NULL, &tv)) == 0)
	{
		close(sock);
		if(print)
			fprintf(stderr, "timed out.\n");
		return(-1);
	}
	else if(c == -1)
	{
		close(sock);
		if(print)
			fprintf(stderr, "select: %.100s (%i)\n", strerror(errno), errno);
		return(-1);
	}

	if(FD_ISSET(sock, &fds))
	{
		if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &l) < 0)
		{
			if(print)
				fprintf(stderr, "getsockopt: %.100s (%i).\n", strerror(errno), errno);
			close(sock);
			return(-1);
		}
	}

	if(err)
	{
		if(print)
			fprintf(stderr, "getsockopt: %.100s (%i).\n", strerror(err), err);
		close(sock);
		return(-1);
	}

	if(print)
		fprintf(stderr, "connected.\n");

	if(unset_nonblocking_mode(sock, oldflags) < 0)
		return(-1);

	return (sock);
}

int set_nonblocking_mode(int fd)
{
	int sockflag;

	if((sockflag = fcntl(fd, F_GETFL, 0)) == -1)
	{
		s_log(eERROR, "could not get flags on fd %d.\n", fd);
		fprintf(stderr, "fcntl(%i, F_GETFL, 0): %.100s (%i)\n", fd, strerror(errno), errno);
		return(-1);
	}

	if(fcntl(fd, F_SETFL, sockflag | O_NONBLOCK) == -1)
	{
		s_log(eERROR, "could not set O_NONBLOCK on socket\n");
		fprintf(stderr, "fcntl(%i, F_SETFL): %.100s (%i)\n", fd, strerror(errno), errno);
		return(-1);
	}

	return(sockflag);
}

int unset_nonblocking_mode(int fd, int oldflags)
{
	if(fcntl(fd, F_SETFL, oldflags&(~O_NONBLOCK)) == -1)
	{
		s_log(eERROR, "could not unset O_NONBLOCK on socket\n");
		return (-1);
	}

	return (0);
}

int data_available(int fd, int sec)
{
	struct timeval timeout;
	fd_set rd;

	timeout.tv_sec = sec;
	timeout.tv_usec = 0;

	FD_ZERO(&rd);
	FD_SET(fd, &rd);

	if(select(FD_SETSIZE, &rd, NULL, NULL, &timeout) == -1)
	{
		s_log(eERROR, "select: %.100s (%i)\n", strerror(errno), errno);
		return(-1);
	}

	if(!FD_ISSET(fd, &rd))
	{
		s_log(eERROR, "select timeout\n");
		return(-1);
	}

	return (1);
}

/* absolutely important that you use in_addr_t for maximum portability */
in_addr_t resolve_host_name(char *hname)
{
	in_addr_t inetaddr;
	struct hostent *h_ent;

	if((inetaddr = inet_addr(hname)) == -1)
	{
		if(!(h_ent = gethostbyname (hname)))
		{
			s_log(eERROR, "can't resolve host %.100s\n", hname);
			fprintf(stderr, "[!] can't resolve host %.100s\n", hname);
			return(-1);
		}

		bcopy(h_ent->h_addr, (char *)&inetaddr, h_ent->h_length);
	}

	return(inetaddr);
}
