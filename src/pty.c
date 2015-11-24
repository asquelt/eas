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
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
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
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#ifdef HAVE_USERSEC_H
#include <usersec.h>
#endif

/* TCP wrapper */
#ifdef HAVE_LIBWRAP
#include <tcpd.h>
int allow_severity=LOG_NOTICE;
int deny_severity=LOG_WARNING;
#endif

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_SYS_TERMIO_H
#include <sys/termio.h>
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif

#include <sys/utsname.h>
#include <pwd.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rand.h"

#include "clientconf.h"
#include "client_id.h"
#include "ssl.h"
#include "socket.h"
#include "log.h"
#include "io.h"
#include "funcs.h"

/* functional delcarations */
char *basename(const char *);
void eash_handshake(void);
void shutdown_pty(int);
void change_window_size(int);
void rawmode(void);
static void signal_handler(int);
int eash_execve(char * const argv[], char * const envp[]);
int eash_setuid(uid_t);
static char *eash_assign_shell(const char *);
static char *eash_parse_shell(const char *);
void eash_validate(void);

#if !defined(HAVE_OPENPTY)
/* we'll just write our own openpty() with an identical API */
int openpty(int *, int *, char *, struct termios *, struct winsize *);
#endif

/* global variables */
static int master_fd, slave_fd;
static struct termios oldttyattr, newttyattr;
static struct winsize wsize;
static struct sigaction sa;
static char slave[BUFSIZ];
char **saved_argv;
static int loginshell = 0;
volatile sig_atomic_t received_sigpipe = 0;

struct ClientOption option;
static SSL_CTX *ctx;
static SSL *ssl;
static struct client_id cid;
struct client_info client;
char *command;
char progname[BUFSIZ];
FILE *fscript;
int sock = -1;

int main(int argc, char **argv, char *envp[])
{
	int c;
	int i;
	int connected = 0;
	struct in_addr dip;
	unsigned short sport = 0;
	unsigned short dport = 0;
	char env_shell[BUFSIZ];
	char env_logname[BUFSIZ];
	char env_path[BUFSIZ];
	char env_term[BUFSIZ];
	char env_home[BUFSIZ];
	char env_user[BUFSIZ];
	char env_display[BUFSIZ];
	char env_login[BUFSIZ];
	char env_name[BUFSIZ];
	char env_tty[BUFSIZ];
	char eash_real_pw_name[BUFSIZ];
	char eash_real_gr_name[BUFSIZ];
	char eash_effective_pw_name[BUFSIZ];
	char eash_effective_gr_name[BUFSIZ];
	char eash_original_pw_name[BUFSIZ];
	char eash_original_gr_name[BUFSIZ];
	char eash_terminal[BUFSIZ];
	char eash_ip[BUFSIZ];
	char eash_real_uid[BUFSIZ];
	char eash_effective_uid[BUFSIZ];
	char eash_original_uid[BUFSIZ];
	char eash_real_gid[BUFSIZ];
	char eash_effective_gid[BUFSIZ];
	char eash_original_gid[BUFSIZ];
	char eash_id[BUFSIZ];
	char eash_command[BUFSIZ];
	char sudo_prompt[BUFSIZ];
	char sudo_command[BUFSIZ];
	char sudo_user[BUFSIZ];
	char sudo_uid[BUFSIZ];
	char sudo_gid[BUFSIZ];
	char sudo_ps1[BUFSIZ];
	char *env_list[63];
	char *assigned_shell;

	strncpy(progname, argv[0], sizeof(progname) - 1);

	init_options();

	if(load_config(EASH_CONFIG) < 0)
	{
		fprintf(stderr, "load_config(%.100s) failed\n", EASH_CONFIG);
		exit(EXIT_FAILURE);
	}

	while((c = getopt(argc, argv, "c:?hvV")) != EOF)
	{
		switch(c)
		{
			case 'c':
				command = strdup(optarg);
				break;
			case 'h':
			case '?':
				fprintf(stdout, "Usage %.63s [-c command [arguments ...]] [-hv] [AUDIT_LOG]\n", basename(progname));
				fprintf(stdout, "Enterprise Audit Shell\n\n");
				fprintf(stdout, " -c\tcommands are read from the following arguement and executed.  Any\n\tremaining arguements are placed in the argv variable.\n");
				fprintf(stdout, " -h\tdisplay this help synopsis.\n");
				fprintf(stdout, " -v\tdisplay version information.\n");
				fprintf(stdout, "\n");
				fprintf(stdout, "Note: if you specified an AUDIT_LOG file, it can be played with with\n");
				fprintf(stdout, "      `eas_play AUDIT_LOG'\n");
				exit(EXIT_SUCCESS);
				break;
			case 'v':
			case 'V':
				fprintf(stdout, "Enterprise Audit Shell version information:\n");
				fprintf(stdout, " + %.63s version %.63s\n", PACKAGE_NAME, PACKAGE_VERSION);
				fprintf(stdout, "\nLibrary information:\n");
				fprintf(stdout, " + OpenSSL version 0x%lx\n", OPENSSL_VERSION_NUMBER);
				exit(EXIT_SUCCESS);
				break;
			default:
				fprintf(stderr, "Try `%.63s -h' for more information.\n", basename(progname));
				exit(EXIT_FAILURE);
				break;
		}
	}

	init_options();

	if(load_config(EASH_CONFIG) < 0)
	{
		fprintf(stderr, "load_config(%.100s) failed\n", EASH_CONFIG);
		exit(EXIT_FAILURE);
	}

	if(get_client_id(&cid) < 0)
		exit(EXIT_FAILURE);

	if((assigned_shell = eash_assign_shell(argv[0])) == (char *) 0)
		exit(EXIT_FAILURE);

	strncpy(cid.shell, assigned_shell, sizeof(cid.shell) - 1);

        argc -= optind;
        argv += optind;

	if(getenv("TERM") != (char *) 0)
		snprintf(env_term, sizeof(env_term) - 1, "TERM=%.63s", getenv("TERM"));
	else
		strncpy(env_term, "TERM=dumb", strlen("TERM=dumb"));

	snprintf(env_home, sizeof(env_home) - 1, "HOME=%.100s", cid.home);
	snprintf(env_logname, sizeof(env_logname) - 1, "LOGNAME=%.63s", cid.real_pw_name);
	snprintf(env_login, sizeof(env_login) - 1, "LOGIN=%.63s", cid.real_pw_name);
	snprintf(env_name, sizeof(env_name) - 1, "NAME=%.63s", cid.real_pw_name);
	snprintf(env_user, sizeof(env_user) - 1, "USER=%.63s", cid.real_pw_name);
	snprintf(env_tty, sizeof(env_tty) - 1, "TTY=%.63s", cid.terminal);

	if(cid.real_uid == 0)
		strncpy(env_path, "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin", sizeof(env_path));
	else
		strncpy(env_path, "PATH=/usr/bin:/bin:/usr/local/bin:", sizeof(env_path));

	memset(eash_real_pw_name, '\0', sizeof(eash_real_pw_name));
	memset(eash_real_gr_name, '\0', sizeof(eash_real_gr_name));
	memset(eash_effective_pw_name, '\0', sizeof(eash_effective_pw_name));
	memset(eash_effective_gr_name, '\0', sizeof(eash_effective_gr_name));
	memset(eash_original_pw_name, '\0', sizeof(eash_original_pw_name));
	memset(eash_original_gr_name, '\0', sizeof(eash_original_gr_name));
	memset(eash_terminal, '\0', sizeof(eash_terminal));
	memset(eash_ip, '\0', sizeof(eash_ip));
	memset(eash_real_uid, '\0', sizeof(eash_real_uid));
	memset(eash_effective_uid, '\0', sizeof(eash_effective_uid));
	memset(eash_original_uid, '\0', sizeof(eash_original_uid));
	memset(eash_real_gid, '\0', sizeof(eash_real_gid));
	memset(eash_effective_gid, '\0', sizeof(eash_effective_gid));
	memset(eash_original_gid, '\0', sizeof(eash_original_uid));
	memset(eash_id, '\0', sizeof(eash_id));
	memset(eash_command, '\0', sizeof(eash_command));

	memset(sudo_prompt, '\0', sizeof(sudo_prompt));
	memset(sudo_command, '\0', sizeof(sudo_command));
	memset(sudo_user, '\0', sizeof(sudo_user));
	memset(sudo_uid, '\0', sizeof(sudo_uid));
	memset(sudo_gid, '\0', sizeof(sudo_gid));
	memset(sudo_ps1, '\0', sizeof(sudo_ps1));

	if(getenv("SUDO_PROMPT"))
		snprintf(sudo_prompt, sizeof(sudo_prompt) - 1, "SUDO_PROMPT=%.127s", getenv("SUDO_PROMPT"));
	if(getenv("SUDO_COMMAND"))
		snprintf(sudo_command, sizeof(sudo_command) - 1, "SUDO_COMMAND=%.127s", getenv("SUDO_COMMAND"));
	if(getenv("SUDO_USER"))
		snprintf(sudo_user, sizeof(sudo_user) - 1, "SUDO_USER=%.127s", getenv("SUDO_USER"));
	if(getenv("SUDO_UID"))
		snprintf(sudo_uid, sizeof(sudo_uid) - 1, "SUDO_UID=%.127s", getenv("SUDO_UID"));
	if(getenv("SUDO_GID"))
		snprintf(sudo_gid, sizeof(sudo_gid) - 1, "SUDO_GID=%.127s", getenv("SUDO_GID"));
	if(getenv("SUDO_PS1"))
		snprintf(sudo_ps1, sizeof(sudo_ps1) - 1, "SUDO_PS1=%.127s", getenv("SUDO_PS1"));

	snprintf(eash_real_pw_name, sizeof(eash_real_pw_name) - 1,
		"EASH_REAL_PW_NAME=%.63s", cid.real_pw_name);
	snprintf(eash_real_gr_name, sizeof(eash_real_gr_name) - 1,
		"EASH_REAL_GR_NAME=%.63s", cid.real_gr_name);
	snprintf(eash_effective_pw_name, sizeof(eash_effective_pw_name) - 1,
		"EASH_EFFECTIVE_PW_NAME=%.63s", cid.effective_pw_name);
	snprintf(eash_effective_gr_name, sizeof(eash_effective_gr_name) - 1,
		"EASH_EFFECTIVE_GR_NAME=%.63s", cid.effective_gr_name);
	snprintf(eash_original_pw_name, sizeof(eash_original_pw_name) - 1,
		"EASH_ORIGINAL_PW_NAME=%.63s", cid.original_pw_name);
	snprintf(eash_original_gr_name, sizeof(eash_original_gr_name) - 1,
		"EASH_ORIGINAL_GR_NAME=%.63s", cid.original_gr_name);

	snprintf(eash_real_uid, sizeof(eash_real_uid) - 1,
		"EASH_REAL_UID=%i", cid.real_uid);
	snprintf(eash_effective_uid, sizeof(eash_effective_uid) - 1,
		"EASH_EFFECTIVE_UID=%i", cid.effective_uid);
	snprintf(eash_original_uid, sizeof(eash_original_uid) - 1,
		"EASH_ORIGINAL_UID=%i", cid.original_uid);
	snprintf(eash_real_gid, sizeof(eash_real_gid) - 1,
		"EASH_REAL_GID=%i", cid.real_gid);
	snprintf(eash_effective_gid, sizeof(eash_effective_gid) - 1,
		"EASH_EFFECTIVE_GID=%i", cid.effective_gid);
	snprintf(eash_original_gid, sizeof(eash_original_gid) - 1,
		"EASH_ORIGINAL_GID=%i", cid.original_gid);

	snprintf(env_shell, sizeof(env_shell) - 1, "SHELL=%.127s", cid.shell);

	/* carefully setup the environment */
	c = 0;

	if(option.copyenv)
	{
		/* initialize env from parent process */
		while (envp[c] != NULL)
			env_list[c] = envp[c++];
	} else {
		/* start from scratch */
#if defined(_AIX)
		env_list[c++] = "USRENVIRON:";
#endif

		env_list[c++] = env_home;
		env_list[c++] = env_path;
		env_list[c++] = env_user;
		env_list[c++] = env_term;
	
		if(getenv("DISPLAY"))
		{
			snprintf(env_display, sizeof(env_display) - 1, "DISPLAY=%.127s", getenv("DISPLAY"));
			env_list[c++] = env_display;
		}

		if(strlen(sudo_prompt))
			env_list[c++] = sudo_prompt;
		if(strlen(sudo_command))
			env_list[c++] = sudo_command;
		if(strlen(sudo_user))
			env_list[c++] = sudo_user;
		if(strlen(sudo_uid))
			env_list[c++] = sudo_uid;
		if(strlen(sudo_gid))
			env_list[c++] = sudo_gid;
		if(strlen(sudo_ps1))
			env_list[c++] = sudo_ps1;
	
#if defined(_AIX)
		/* weird AIX bug?  If you have too many entries below SYSENVION: it just .. breaks */
		env_list[c++] = "SYSENVIRON:";
#endif
		env_list[c++] = env_login;
		env_list[c++] = env_name;
		env_list[c++] = env_logname;
		env_list[c++] = env_tty;
	}

	env_list[c++] = env_shell;

	env_list[c++] = eash_real_pw_name;
	env_list[c++] = eash_real_gr_name;
	env_list[c++] = eash_effective_pw_name;
	env_list[c++] = eash_effective_gr_name;
	env_list[c++] = eash_original_pw_name;
	env_list[c++] = eash_original_gr_name;
	env_list[c++] = eash_real_uid;
	env_list[c++] = eash_effective_uid;
	env_list[c++] = eash_original_uid;
	env_list[c++] = eash_real_gid;
	env_list[c++] = eash_effective_gid;
	env_list[c++] = eash_original_gid;

	/* ENV TERMINATE */
	env_list[c++] = (char *) 0;

	SSL_library_init();
	SSL_load_error_strings();
	ssl_seed(option.egdfile, option.randomfile);

	if(ssl_init_accept(&ctx, option.method, option.pemfile, option.cafiles, (char *) 0) < 0)
		exit(EXIT_FAILURE);

	/* no longer need our root privileges - let's give them up */
	/* eash_setuid() will take care of AIX-specific credentials as well */
	if(eash_setuid(cid.real_uid) < 0)
		exit(EXIT_FAILURE);

	c = 0;

	while(option.log_servers[c] && connected == 0)
	{
		if((dip.s_addr = resolve_host_name(option.log_servers[c])) == -1)
		{
			c++;
			continue;
		}

		dport = option.port;
		if(!command)
			log_or_term(stderr, "[i] trying %.100s:%d ... ", inet_ntoa(dip), dport);

		if((sock = ssl_connect_ip(&dip, dport, sport, &ssl, &ctx, option.method, option.tcptimeout, command ? 0 : option.shutup ? 0 : 1)) == -1)
		{
			c++;
		}
		else
		{
			connected = 1;
		}
	}

	if(connected == 0)
	{
		fprintf(stderr, "[i] exhausted list of log servers.\n");
		if(loginshell)
		{
			log_or_term(stderr, "(detected login shell - intentional 5 second pause)\n");
			sleep(5);
		}
		exit(EXIT_FAILURE);
	}

	eash_handshake();
	eash_validate();

        /* skip logging contents of non-interactive non-pty shell sessions */
        if( command && 
            ( isatty(STDIN_FILENO) == 0 ||
              isatty(STDOUT_FILENO) == 0 ||
              isatty(STDERR_FILENO) == 0 ||
              getlogin() == NULL 
            )
          )
        {
            char *av[6];
            av[0] = "/bin/bash";
            av[1] = "-bash";
            av[2] = "-c";
            av[3] = command;
            av[4] = 0;

            if(eash_execve(av, env_list) < 0)
               exit(EXIT_FAILURE);
            /* this shouldn't happen */
            exit(EXIT_FAILURE);
        }

	if(*argv)
	{
		if((fscript = fopen(*argv, "w")) == (FILE *) 0)
		{
			log_or_term(stderr, "fopen: %.100s: %.100s (%i)\n", *argv, strerror(errno), errno);
			exit(EXIT_FAILURE);
		}
	}

	/* get window size */
	ioctl(STDIN_FILENO, TIOCGWINSZ, &wsize);
	rawmode();

	if(openpty(&master_fd, &slave_fd, slave, NULL, NULL) < 0)
	{
		log_or_term(stderr, "openpty: %.100s (%i)\n", strerror(errno), errno);
		shutdown_pty(1);
		exit(EXIT_FAILURE);
	}

	switch(fork())
	{
		case 0:
			close(STDIN_FILENO);
			close(STDOUT_FILENO);
			close(STDERR_FILENO);

			setsid();

			if((slave_fd = open(slave, O_RDWR)) < 0)
			{
				log_or_term(stderr, "open(%.100s): %.100s (%i)\n", slave, strerror(errno), errno);
				shutdown_pty(1);
				exit(EXIT_FAILURE);
			}
#ifdef TIOCSCTTY
			if(ioctl(STDIN_FILENO, TIOCSCTTY, NULL) < 0)
			{
				log_or_term(stderr, "ioctl: %.100s (%i)\n", strerror(errno), errno);
				shutdown_pty(1);
				exit(EXIT_FAILURE);
			}
#endif
			/*
			dup2(slave_fd, STDIN_FILENO);
			dup2(slave_fd, STDOUT_FILENO);
			dup2(slave_fd, STDERR_FILENO);
			*/

			dup(STDIN_FILENO);
			dup(STDIN_FILENO);

			for(i = 3; i < 100; i++)
				close(i);

			/* set previous terminal attributes and window size to the new shell */
			/* ioctl(STDIN_FILENO, TCSETS, &oldttyattr); */
			tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldttyattr);
			ioctl(STDIN_FILENO, TIOCSWINSZ, &wsize);

			if(option.banner)
			{
				FILE *f;
				char buffer[BUFSIZ];

				memset(buffer, '\0', sizeof(buffer));

				if((f = fopen(option.banner, "r")) != (FILE *) 0)
				{
					while(fgets(buffer, sizeof(buffer) - 1, f))
						fputs(buffer, stdout);
					memset(buffer, '\0', sizeof(buffer));
				}
				else
				{
					log_or_term(stderr, "%.63s: warning: %.100s: %.100s (%i)\n", basename(progname), option.banner, strerror(errno), errno);
				}

				if(option.banner_pause > 0)
					sleep(option.banner_pause);
			}	

			/*
			setuid(getuid());
			*/

			/* shell was called with the -c, thus we need to execute a command instead of a shell */
			if(command)
			{
				char *av[5];

				av[0] = "/bin/bash";
				av[1] = "-bash";
				av[2] = "-c";
				av[3] = command;
				av[4] = 0;

				if(chdir(cid.home) < 0)
					log_or_term(stderr, "%.63s: warning: chdir(%.127s): %.100s (%i)\n",
						basename(progname), cid.home, strerror(errno), errno);

				if(eash_execve(av, env_list) < 0)
					exit(EXIT_FAILURE);
			}
			else
			{
				char *av[6];
				char newarg[BUFSIZ];

				snprintf(newarg, sizeof(newarg) - 1, "-%.127s", basename(cid.shell));

                                if(option.copyenv)
                                {
                                        av[0] = cid.shell; /* shell of real uid */
                                        av[1] = newarg; /* basename of the shell of the real uid prepended with a single - */
                                        av[2] = 0;
                                } else {
                                        av[0] = "/bin/bash";
                                        av[1] = "-bash";
                                        av[2] = "-c";
                                        av[3] = cid.shell; /* shell of real uid */
                                        av[4] = newarg; /* basename of the shell of the real uid prepended with a single - */
                                        av[5] = 0;
                                }

				if(chdir(cid.home) < 0)
					log_or_term(stderr, "%.63s: warning: chdir(%.127s): %.100s (%i)\n",
						basename(progname), cid.home, strerror(errno), errno);

				if(eash_execve(av, env_list) < 0)
				{
					log_or_term(stderr, "debug: eash_execve -1\n");
					exit(EXIT_FAILURE);
				}
			}

			fprintf(stderr, "%.63s: [%.63s, %i]: this should never happen.\n", basename(progname), __FILE__, __LINE__);
			exit(EXIT_FAILURE);

			break;
		case -1:
			log_or_term(stderr, "fork(): %.100s (%i)\n", strerror(errno), errno);
			shutdown_pty(1);
			exit(EXIT_FAILURE);
			break;
		default:
			close(slave_fd);
			break;
	}

	setuid(getuid());

	memset(&sa, 0, sizeof sa);

	sa.sa_handler = change_window_size;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGWINCH, &sa, (struct sigaction *) 0);

	sa.sa_handler = signal_handler;
	sa.sa_flags = 0;
	sigaction(SIGHUP, &sa, (struct sigaction *) 0);

	sa.sa_handler = signal_handler;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, (struct sigaction *) 0);

	sa.sa_handler = signal_handler;
	sa.sa_flags = 0;
	sigaction(SIGQUIT, &sa, (struct sigaction *) 0);

	sa.sa_handler = signal_handler;
	sa.sa_flags = 0;
	sigaction(SIGTERM, &sa, (struct sigaction *) 0);

	sa.sa_handler = signal_handler;
	sa.sa_flags = 0;
	sigaction(SIGABRT, &sa, (struct sigaction *) 0);

	sa.sa_handler = signal_handler;
	sa.sa_flags = 0;
	sigaction(SIGCHLD, &sa, (struct sigaction *) 0);

	sa.sa_handler = signal_handler;
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, (struct sigaction *) 0);

	while(1)
	{
		fd_set fds;
		int n;
		char buf[BSIZ];

		FD_ZERO(&fds);
		FD_SET(master_fd, &fds);
		FD_SET(sock, &fds);
		FD_SET(STDIN_FILENO, &fds);

		if(received_sigpipe)
		{
			log_or_term(stderr, "%.63s: received SIGPIPE: exitting immediately.\n", basename(progname));
			shutdown_pty(1);
			exit(EXIT_FAILURE);
		}

		memset(buf, '\0', sizeof(buf));
		if(select(FD_SETSIZE, &fds, NULL, NULL, NULL) <= 0)
		{
			if(errno == EINTR)
				continue;

			log_or_term(stderr, "select: %.100s (%i)\n", strerror(errno), errno);
			shutdown_pty(1);
			exit(EXIT_FAILURE);
		}

		/* socket output */
		memset(buf, '\0', sizeof(buf));
		if(FD_ISSET(sock, &fds))
		{
			if((n = read(sock, buf, sizeof(buf) - 1)) <= 0)
			{
				if(n == 0)
					break;

				if(errno == EWOULDBLOCK || errno == EAGAIN)
				{
					continue;
				}
				else
				{
					log_or_term(stderr, "[!] connection closed by foriegn host.\n");
					break;
				}
			}
		}

		/* shell output */
		memset(buf, '\0', sizeof(buf));
		if(FD_ISSET(master_fd, &fds))
		{
			Header h;

			if((n = read(master_fd, buf, sizeof(buf) - 1)) <= 0)
			{
				if(n == 0)
					break;

				if(errno == EWOULDBLOCK || errno == EAGAIN)
					continue;
				else
					break;
			}

			if(write(STDIN_FILENO, buf, n) != n)
			{
				log_or_term(stderr, "%.63s: output write(%i): %.100s (%i)\n", basename(progname), STDIN_FILENO, strerror(errno), errno);
				shutdown_pty(1);
				exit(EXIT_FAILURE);
			}

			if(ssl_write(ssl, buf, n) < 0)
			{
				log_or_term(stderr, "%.63s: output: ssl_write:\n", basename(progname));
				shutdown_pty(1);
				exit(EXIT_FAILURE);
			}

			if(fscript)
			{
				h.len = n;
				gettimeofday(&h.tv, NULL);
				write_header(fscript, &h);
				fwrite(buf, 1, n, fscript);
				fflush(fscript);
			}
		}

		/* user input */
		memset(buf, '\0', sizeof(buf));
		if(FD_ISSET(STDIN_FILENO, &fds))
		{
			if((n = read(STDIN_FILENO, buf, sizeof(buf) - 1)) <= 0)
			{
				if(n == 0)
					break;

				if(errno == EWOULDBLOCK || errno == EAGAIN)
					continue;
				else
				{
					log_or_term(stderr, "read(%i): %.100s (%i)\n", STDIN_FILENO, strerror(errno), errno);
					break;
				}
			}

			if(write(master_fd, buf, n) != n)
			{
				log_or_term(stderr, "%.63s: input write(%i): %.100s (%i)\n", basename(progname), master_fd, strerror(errno), errno);
				shutdown_pty(1);
				exit(EXIT_FAILURE);
			}
		}
	}

	shutdown_pty(0);
	exit(EXIT_SUCCESS);
}

void shutdown_pty(int error)
{
	signal(SIGWINCH, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGABRT, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	/* restore old terminal attributes */
	/* ioctl(STDIN_FILENO, TCSETS, &oldttyattr); */
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldttyattr);
	if(fscript)
		fclose(fscript);
	/*
	if(!command && !error)
		system("clear");
	*/
	if(!command && !error)
		log_or_term(stderr, "(eash closed)\n");
	return;
}

void change_window_size(int dummy)
{
	signal(SIGWINCH, SIG_IGN);

	/* get the new window size from stdin */
	if(ioctl(STDIN_FILENO, TIOCGWINSZ, &wsize) != -1)
	{
		/* set the new window size to the pty shell */
		ioctl(master_fd, TIOCSWINSZ, &wsize);
	}

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = change_window_size;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGWINCH, &sa, (struct sigaction *) 0);
	signal(SIGWINCH, change_window_size);

	return;
}

static void signal_handler(int signum)
{
	switch(signum)
	{
		case SIGHUP:
			log_or_term(stdout, "HUP\n");
			break;
		case SIGCHLD:
			waitpid(-1, NULL, WNOHANG);
			break;
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
		case SIGABRT:
			log_or_term(stderr, "[!] forcefully stopped.\n");
			shutdown_pty(0);
			exit(EXIT_SUCCESS);
			break;
		case SIGPIPE:
			received_sigpipe = 1;
			break;
		default:
			break;
	}

	return;
}

void rawmode(void)
{
	/* get terminal attributes */
	tcgetattr(STDIN_FILENO, &oldttyattr);
	/* ioctl(STDIN_FILENO, TCGETS, &oldttyattr); */

#ifdef HAVE_CFMAKERAW
	/* save old settings and make this terminal raw */
	newttyattr = oldttyattr;
	cfmakeraw(&newttyattr);
#endif

	newttyattr.c_cc[VEOF] = 1;
	if (option.flowcontrol)
	{
		newttyattr.c_iflag = BRKINT | ISTRIP | IXON | IXANY;
	} else {
		newttyattr.c_iflag = 0;
	}
	newttyattr.c_oflag = 0;
	newttyattr.c_cflag = oldttyattr.c_cflag;
	newttyattr.c_lflag &= ~ECHO;

	/* ioctl(STDIN_FILENO, TCSETS, &newttyattr); */
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &newttyattr);
}

void eash_handshake(void)
{
	struct utsname u;
	char data[4096];

	if(uname(&u) < 0)
	{
		log_or_term(stderr, "uname: %.100s (%i)\n", strerror(errno), errno);
		shutdown_pty(1);
		exit(EXIT_FAILURE);
	}

	memset(data, '\0', sizeof(data));
	if(command)
		snprintf(data, sizeof(data) - 1, "HELO\aCOMMAND\a%.100s\a%.100s\a%.100s\a%.100s\a%.100s\a%.900s\n", u.sysname, u.nodename, u.release, u.version, u.machine, command);
	else if(loginshell)
		snprintf(data, sizeof(data) - 1, "HELO\aLOGIN\a%.100s\a%.100s\a%.100s\a%.100s\a%.100s\a%.900s\n", u.sysname, u.nodename, u.release, u.version, u.machine, "null");
	else
		snprintf(data, sizeof(data) - 1, "HELO\aSESSION\a%.100s\a%.100s\a%.100s\a%.100s\a%.100s\a%.900s\n", u.sysname, u.nodename, u.release, u.version, u.machine, "null");
	ssl_write(ssl, data, strlen(data));
	ssl_write(ssl, cid.user_string, strlen(cid.user_string));
	return;
}

int eash_setuid(uid_t uid)
{
#if defined(_AIX)
	if(setpcred(getpwuid(uid)->pw_name, 0) < 0)
	{
		log_or_term(stderr, "setpcred(%i, NULL): %.100s (%i)\n", uid, strerror(errno), errno);
		return(-1);
	}
#else
	if(setuid(uid) < 0)
	{
		log_or_term(stderr, "setuid(%i): %.100s (%i)\n", uid, strerror(errno), errno);
		return(-1);
	}
#endif

	return(0);
}

int eash_execve(char * const argv[], char * const envp[])
{
	register int i = 0;
#if defined(_AIX)
	/* setpenv likes argv to be in the format of execv when used with PENV_INIT */
	if(setpenv(cid.real_pw_name, PENV_ARGV|PENV_INIT, (char **) envp, (char *) argv) < 0)
	{
		log_or_term(stderr, "setpenv(%.63s, PENV_ARGV|PENV_INIT, envp, argv): %.100s (%i)\n", cid.real_pw_name, strerror(errno), errno);

		for(i = 0; envp[i]; i++)
			log_or_term(stderr, "debug: envp[%i] = %.127s\n", i, envp[i]);
		for(i = 0; argv[i]; i++)
			log_or_term(stderr, "debug: argv[%i] = %.127s\n", i, argv[i]);

		return(-1);
	}

	log_or_term(stderr, "internal error: setpenv(%.63s): %.100s (%i)\n", cid.real_pw_name, strerror(errno), errno);
	return(-1);
#else
	/* argv[0] = filename
	*  argv + 1 = execve formatted argv */
	execve(argv[0], argv + 1, envp);

	log_or_term(stderr, "internal error: execve(%.127s, argv, envp): %.100s (%i)\n", argv[0], strerror(errno), errno);

	for(i = 0; argv[i]; i++)
		log_or_term(stderr, "debug: argv[%i] = %.127s\n", i, argv[i]);
	for(i = 0; envp[i]; i++)
		log_or_term(stderr, "debug: envp[%i] = %.127s\n", i, envp[i]);

	return(-1);
#endif
}

static char *eash_assign_shell(const char *arg)
{
	static char _shell[BUFSIZ];
	char original_arg[BUFSIZ];
	char *arg_ptr;

	memset(_shell, '\0', sizeof(_shell));

	/* copy arg */
	memset(original_arg, '\0', sizeof(original_arg));
	strncpy(original_arg, arg, sizeof(original_arg) - 1);

	arg_ptr = original_arg;

	/* is this a login shell? */
	if(*arg_ptr == '-')
	{
		arg_ptr++;

		if(!strcmp(arg_ptr, "eash"))
		{
			strncpy(_shell, option.default_shell, sizeof(_shell) - 1);
			return(_shell);
		}
		else if(strchr(arg_ptr, '_'))
		{
			char *parsed_shell_ptr;

			if((parsed_shell_ptr = eash_parse_shell(arg_ptr)) == (char *) 0)
				return(0);

			strncpy(_shell, parsed_shell_ptr, sizeof(_shell) - 1);
			return(_shell);
		}
		else
		{
			fprintf(stderr, "%.63s: this binary was called as something other than \"eash\".\n", basename(progname));
			fprintf(stderr, "This binary needs to be called as \"eash\".  If you were trying to specify\n");
			fprintf(stderr, "a custom shell via the symlink option, please use the format:\n");
			fprintf(stderr, "eash_path_to_shell\n");
			return(0);
		}
	}
	else
	{
		if(getenv("SHELL"))
		{
			char *env_shell = getenv("SHELL");
			char *env_shell_ptr = basename(env_shell);

			if(!strcmp("eash", env_shell_ptr))
			{
				strncpy(_shell, option.default_shell, sizeof(_shell) - 1);
				return(_shell);
			}
			else if(strchr(env_shell_ptr, '_'))
			{
				char *parsed_shell_ptr;

				if((parsed_shell_ptr = eash_parse_shell(env_shell_ptr)) == (char *) 0)
					return(0);

				strncpy(_shell, parsed_shell_ptr, sizeof(_shell) - 1);
				return(_shell);
			}
			else
			{

				if(validshell(env_shell) < 0)
				{
					fprintf(stderr, "%.63s: %.127s: not in /etc/shells\n", basename(progname), env_shell);
					return(0);
				}
				else
				{
					strncpy(_shell, env_shell, sizeof(_shell) - 1);
					return(_shell);
				}
			}
		}
		else
		{
			/* the user's shell as defined in /etc/passwd is "eash" - use the DefaultShell */
			if(!strcmp("eash", arg_ptr))
			{
				strncpy(_shell, option.default_shell, sizeof(_shell) - 1);
				return(_shell);
			}
			else if(strchr(arg_ptr, '_'))
			{
				char *parsed_shell_ptr;

				if((parsed_shell_ptr = eash_parse_shell(arg_ptr)) == (char *) 0)
					return(0);

				strncpy(_shell, parsed_shell_ptr, sizeof(_shell) - 1);
				return(_shell);
			}
			/* just use the user's regular shell as defined in /etc/passwd */
			else
			{
				strncpy(_shell, option.default_shell, sizeof(_shell) - 1);
				return(_shell);
			}
		}
	}

	/* code never reached */
	log_or_term(stderr, "%.63s: internal error: eash_assign_shell: reached non-reachable code.\n", basename(progname));
	return(0);
}

static char *eash_parse_shell(const char *str)
{
	static char shell[BUFSIZ];
	char *shell_ptr;
	char *ptr;
	

	if((ptr = strchr(str, '_')))
	{
		for(shell_ptr = shell; *ptr; shell_ptr++, ptr++)
		{
			if(*ptr == '_')
				*ptr = '/';

			*shell_ptr = *ptr;
		}

		if(validshell(shell) < 0)
		{
			fprintf(stderr, "%.63s: %.127s: not in /etc/shells\n", basename(progname), shell);
			return(0);
		}
		else
		{
			return(shell);
		}
	}

	log_or_term(stderr, "%.63s: internal error: eash_parse_shell: nothing to parse: str = '%.127s'\n", basename(progname), str);
	return(0);
}

void eash_validate(void)
{
	if(!command)
		log_or_term(stderr, "Awaiting EAS central server validation ... ");
	while(1)
	{
		fd_set fds;
		int n;
		char buf[BSIZ];

		FD_ZERO(&fds);
		FD_SET(sock, &fds);

		if(received_sigpipe)
		{
			log_or_term(stderr, "%.63s: received SIGPIPE: exitting immediately.\n", basename(progname));
			shutdown_pty(1);
			exit(EXIT_FAILURE);
		}

		memset(buf, '\0', sizeof(buf));
		if(select(FD_SETSIZE, &fds, NULL, NULL, NULL) <= 0)
		{
			if(errno == EINTR)
				continue;

			log_or_term(stderr, "select: %.100s (%i)\n", strerror(errno), errno);
			exit(EXIT_FAILURE);
		}

		/* socket output */
		memset(buf, '\0', sizeof(buf));
		if(FD_ISSET(sock, &fds))
		{
			if((n = ssl_readline(ssl, buf, sizeof(buf) - 1)) <= 0)
			{
				log_or_term(stderr, "%.63s: [%.63s, %i]: ssl_readline = %i\n", basename(progname), __FILE__, __LINE__, n);
				exit(EXIT_FAILURE);
			}

			if(buf[strlen(buf) - 1] == '\n')
				buf[strlen(buf) - 1] = '\0';

			if(!strcmp(buf, "OK"))
			{
				if(!command)
					log_or_term(stderr, "granted.\n");
				return;
			}
			else if(!strcmp(buf, "DENY TIMEOUT"))
			{
				if(!command)
					log_or_term(stderr, "denied (reason: hook timeout).\n");
				else
					log_or_term(stderr, "%.63s: EAS central server has denied your request (reason: hook timeout).\n", basename(progname));
				exit(EXIT_FAILURE);
			}
			else if(!strcmp(buf, "DENY EVAL"))
			{
				if(!command)
					log_or_term(stderr, "denied (reason: trail-version - expired).\n");
				else
					log_or_term(stderr, "%.63s: EAS central server has denied your request (reason: trail-version - expired).\n", basename(progname));
				exit(EXIT_FAILURE);
			}
			else if(!strcmp(buf, "DENY HOOK"))
			{
				if(!command)
					log_or_term(stderr, "denied (reason: hook returned non-zero).\n");
				else
					log_or_term(stderr, "%.63s: EAS central server has denied your request (reason: hook returned non-zero).\n", basename(progname));
				exit(EXIT_FAILURE);
			}
			else
			{
				if(!command)
					log_or_term(stderr, "denied (reason: none specified).\n");
				else
					log_or_term(stderr, "%.63s: EAS central server has denied your request (reason: none specified).\n", basename(progname));
				exit(EXIT_FAILURE);
			}
		}
	}
}

void log_or_term(FILE *stream, const char *fmt, va_list args)
{
	/* BUG: i can't make it log
	if(option.shutup)
	        c_log(eINFO, fmt, args);
	else
		fprintf(stream, fmt, args);
	*/

	if(!option.shutup)
		fprintf(stream, fmt, args);
}
