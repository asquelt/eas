#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rand.h"

#include "config.h"

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
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

/* TCP wrapper */
#ifdef HAVE_LIBWRAP
#include <tcpd.h>
int allow_severity=LOG_NOTICE;
int deny_severity=LOG_WARNING;
#endif

#include "sig.h"
#include "client_id.h"
#include "ssl.h"
#include "socket.h"
#include "log.h"
#include "servconf.h"

extern struct ServerOption option;
extern struct client_info client;
extern char **saved_argv;

int timer = 0;
int uptime = 0;
static int mark = 60*60;
volatile sig_atomic_t received_sighup = 0;
volatile sig_atomic_t received_sigusr1 = 0;
volatile sig_atomic_t received_shutdown = 0;

volatile sig_atomic_t received_sigchld = -1;

void sighup_restart(void)
{
	char cwd[BUFSIZ];

	ssl_close_connection(option.ssl, option.ctx);
	shutdown(option.sock, SHUT_RDWR);
	close(option.sock);
	unlink(option.pidfile);
	s_log(eDEBUG1, "listen socket shutdown and closed");
	s_log(eDEBUG2, "execv(%s)", saved_argv[0]);
	switch(fork())
	{
		case -1:
			s_log(eERROR, "fork: %.100s (%i)", strerror(errno), errno);
			exit(EXIT_FAILURE);
			break;
		case 0:
			break;
		default:
			exit(EXIT_SUCCESS);
	}
	execv(saved_argv[0], saved_argv);
	s_log(eERROR, "RESTART FAILED");
	if(getcwd(cwd, sizeof(cwd) - 1))
		s_log(eERROR, "CURRENT WORKING DIRECTORY: %.100s", cwd);
	else
		s_log(eERROR, "getcwd: %.100s (%i)", strerror(errno), errno);
	s_log(eERROR, "HINT: this error happens if you do not execute easd with the absolute path.  Always use the absolute path.");
	s_log(eERROR, "execv(%s): %.100s (%i)", saved_argv[0], strerror(errno), errno);
	exit(EXIT_FAILURE);
}

void reset_timer(void)
{
	stop_timer();
	timer = 0;
	uptime = 0;
	mark = 60*60;
	init_timer();
}

int duration(void)
{
	return uptime;
}

void timer_click(void)
{
	switch(mark)
	{
		case 0:
			mark = 60*60;
			s_log(eINFO, "--MARK--");
			break;
		default:
			mark--;
			break;
	}

	uptime++;

	if(client.cid.real == 1 && option.idletimeout > 60)
	{
		client.cid.idle++;

		if(client.cid.idle > option.idletimeout)
		{
			s_log(eINFO, "%.63s@%.100s being kicked for exceeding the idle timeout of %i seconds.", client.cid.original_pw_name, client.where, option.idletimeout);
			client.cid.eject = 1;
		}
	}

	return;
}

void signal_ALRM(int dummy)
{
	if(timer)
		timer--;
	else
	{
		timer_click();
		timer = CLICK_RATE;
	}

	return;
}

static void signal_handler(int signum)
{
	pid_t pid;
	int stat;

	switch(signum)
	{
		case SIGHUP:
			s_log(eINFO, "SIGHUP received - restarting");
			received_sighup = 1;
			break;
		case SIGCHLD:
			while((pid = waitpid(-1, &stat, WNOHANG)) > 0 || (pid < 0 && errno == EINTR))
			{
				s_log(eDEBUG1, "waitpid: reaped child %i with a return code of %i", pid, stat);
				received_sigchld = stat;
			}
			break;
		case SIGUSR1:
			s_log(eINFO, "SIGUSR1 received - changing LogLevel");
			received_sigusr1 = 1;
			break;
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
		case SIGABRT:
		case SIGPIPE:
			s_log(eINFO, "easd stopped.\n");
			received_shutdown = 1;
			break;
		case SIGALRM:
			signal_ALRM(0);
		default:
			break;
	}

	return;
}

void init_signal(void)
{
	struct sigaction sa;

	sa.sa_flags = 0;

	sa.sa_handler = signal_handler;
	sigaction(SIGINT, &sa, 0);

	sa.sa_handler = signal_handler;
	sigaction(SIGQUIT, &sa, 0);

	sa.sa_handler = signal_handler;
	sigaction(SIGTERM, &sa, 0);

	sa.sa_handler = signal_handler;
	sigaction(SIGABRT, &sa, 0);

	sa.sa_handler = signal_handler;
	sigaction(SIGCHLD, &sa, 0);

	sa.sa_handler = signal_handler;
	sigaction(SIGUSR1, &sa, 0);

	sa.sa_handler = signal_handler;
	sigaction(SIGUSR2, &sa, 0);

	sa.sa_handler = signal_ALRM;
	sigaction(SIGALRM, &sa, 0);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, signal_handler);
}

void stop_timer(void)
{
	struct itimerval t;

	t.it_interval.tv_usec = 0;
	t.it_interval.tv_sec = 0;
	t.it_value.tv_usec = 0;
	t.it_value.tv_sec = 0;

	if(setitimer(ITIMER_REAL, &t, 0) < 0)
	{
		s_log(eERROR, "cannot stop timer: setitimer: %.100s (%i)\n", strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
}

void init_timer(void)
{
	struct itimerval t;

	t.it_interval.tv_usec = 1000000 / CLICK_RATE;
	t.it_interval.tv_sec = 0;
	t.it_value.tv_usec = 1000000 / CLICK_RATE;
	t.it_value.tv_sec = 0;

	if (setitimer (ITIMER_REAL, &t, 0) < 0)
	{
		s_log(eERROR, "failed to start timer: setitimer: %.100s (%i)\n", strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	timer = CLICK_RATE;
	return;

}
