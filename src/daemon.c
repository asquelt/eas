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

/* TCP wrapper */
#ifdef HAVE_LIBWRAP
#include <tcpd.h>
int allow_severity=LOG_NOTICE;
int deny_severity=LOG_WARNING;
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
#include "funcs.h"

#include "../sqlite/sqlite3.h"

/* function declarations */
int become_daemon1(void);
int become_daemon2(void);
void init_client(struct client_info *);
void sql_client_logoff(struct client_info *);
extern volatile sig_atomic_t received_sighup;
extern volatile sig_atomic_t received_sigusr1;
extern volatile sig_atomic_t received_shutdown;

/* globals */
struct ServerOption option;
char *sslprotocols[] = { "TLSv1", "SSLv2", "SSLv3", "SSLv23", 0 };
char *daemons[] = { "inetd", "stand-alone", "once", 0 };
char **saved_argv;
struct client_info client;

int main(int argc, char **argv)
{
	int client_fd = -1;
	int i;
	int c;

	init_client(&client);

	saved_argv = malloc(sizeof(*saved_argv) * (argc + 1));
	for(i = 0; i < argc; i++)
		saved_argv[i] = strdup(argv[i]);
	saved_argv[i] = 0;

	init_options();
	if(load_config(EASHD_CONFIG) < 0)
	{
		s_log(eERROR, "load_config(%.100s) failed.", EASHD_CONFIG);
		exit(EXIT_FAILURE);
	}

	while((c = getopt(argc, argv, "?hvV")) != EOF)
	{
		switch(c)
		{
			case 'h':
			case '?':
				fprintf(stdout, "Usage: %.63s [-hv]\n", basename(*argv));
				fprintf(stdout, "Enterprise Audit Shell Daemon\n\n");
				fprintf(stdout, " -h\tdisplay this help synopsis.\n");
				fprintf(stdout, " -v\tdisplay version information.\n");
				exit(EXIT_SUCCESS);
				break;
			case 'v':
			case 'V':
				print_version(&option, *argv);
				exit(EXIT_SUCCESS);
				break;
			default:
				fprintf(stderr, "Try `%.63s -h' for more information.\n", basename(*argv));
				exit(EXIT_FAILURE);
				break;
		}
	}

	if(option.uid != -1)
	{
		if(chown(option.sessiondirectory, option.uid, option.gid) < 0)
		{
			fprintf(stderr, "chown(%.100s, %i, %i): %.100s (%i)\n", option.sessiondirectory, option.uid, option.gid, strerror(errno), errno);
			exit(EXIT_FAILURE);
		}
	}

	if(become_daemon1() < 0)
	{
		s_log(eERROR, "become_daemon1() failed.");
		exit(EXIT_FAILURE);
	}

	if(sql_init_db(option.sessiondb) < 0)
		exit(EXIT_FAILURE);

	if(option.uid != -1)
	{
		if(chown(option.sessiondb, option.uid, option.gid) < 0)
		{
			fprintf(stderr, "chown(%.100s, %i, %i): %.100s (%i)\n", option.sessiondb, option.uid, option.gid, strerror(errno), errno);
			exit(EXIT_FAILURE);
		}
	}

	s_log(eDEBUG2, "calling SSL_library_init");
	SSL_library_init();

	s_log(eDEBUG2, "calling SSL_load_error_strings");
	SSL_load_error_strings();

	s_log(eDEBUG2, "calling ssl_seed");
	ssl_seed(option.egdfile, option.randomfile);

	s_log(eDEBUG2, "calling ssl_init_accept");
	if(ssl_init_accept(&option.ctx, option.method, option.pemfile, option.cafiles, option.cipher) < 0)
	{
		unlink(option.pidfile);
		exit(EXIT_FAILURE);
	}

	s_log(eDEBUG2, "calling listen_sock");
	if((option.sock = listen_sock(option.port)) < 0)
	{
		unlink(option.pidfile);
		exit(EXIT_FAILURE);
	}

	strncpy(client.cid.method, sslprotocols[option.eash_method], sizeof(client.cid.method) - 1);
	s_log(eDEBUG1, "using %.15s encryped communication.", client.cid.method);
	if(option.cipher)
		s_log(eDEBUG1, "using configured ciphers: %.100s", option.cipher);
	s_log(eDEBUG1, "listening for incoming connections on port %d.", option.port);

	if(become_daemon2() < 0)
	{
		s_log(eERROR, "become_daemon2() failed.");
		unlink(option.pidfile);
		exit(EXIT_FAILURE);
	}

	s_log(eDEBUG2, "calling init_signal");
	init_signal();

	s_log(eDEBUG2, "calling init_timer");
	init_timer();

	s_log(eINFO, "easd started");

	if(option.uid != -1)
	{
		if(setgid(option.gid) < 0)
		{
			fprintf(stderr, "setgid(%i): %.100s (%i)\n", option.gid, strerror(errno), errno);
			s_log(eERROR, "setgid(%i): %.100s (%i)", option.gid, strerror(errno), errno);
			unlink(option.pidfile);
			exit(EXIT_FAILURE);
		}

		if(setuid(option.uid) < 0)
		{
			fprintf(stderr, "setuid(%i): %.100s (%i)\n", option.uid, strerror(errno), errno);
			s_log(eERROR, "setuid(%i): %.100s (%i)", option.uid, strerror(errno), errno);
			unlink(option.pidfile);
			exit(EXIT_FAILURE);
		}
	}

	while(!received_shutdown)
	{
		pid_t pid;

		if(received_sighup)
			sighup_restart();
		if(received_sigusr1)
		{
			received_sigusr1 = 0;

			switch(option.level)
			{
				case eINFO:
					s_log(eINFO, "Current LogLevel = INFO");
					s_log(eINFO, "New LogLevel = DEBUG1");
					option.level = eDEBUG1;
					break;
				case eDEBUG1:
					s_log(eINFO, "Current LogLevel = DEBUG1");
					s_log(eINFO, "New LogLevel = DEBUG2");
					option.level = eDEBUG2;
					break;
				case eDEBUG2:
					s_log(eINFO, "Current LogLevel = DEBUG2");
					s_log(eINFO, "New LogLevel = DEBUG3");
					option.level = eDEBUG3;
					break;
				case eDEBUG3:
					s_log(eINFO, "Current LogLevel = DEBUG3");
					s_log(eINFO, "New LogLevel = INFO");
					option.level = eINFO;
					break;
				default:
					s_log(eINFO, "Current LogLevel = UNKNOWN");
					s_log(eINFO, "New LogLevel = INFO");
					option.level = eINFO;
					break;
			}
		}

		s_log(eDEBUG2, "calling wait_for_connect_daemon(%i, %x)", option.sock, &client);
		if((client_fd = wait_for_connect(option.sock, &client)) == -1)
		{
			unlink(option.pidfile);
			exit(EXIT_FAILURE);
		}

		if(client_fd == -2)
			continue;

		s_log(eDEBUG1, "calling fork");

		if((pid = fork()) == 0)
		{
			reset_timer();

			s_log(eDEBUG1, "new connection - forking child %i\n", getpid());
			s_log(eDEBUG1, "calling close(%i)", option.sock);
			close(option.sock);

			s_log(eDEBUG2, "calling ssl_wait_for_connection(%i, %i, %x, %x)", option.sock, client_fd, option.ssl, option.ctx);
			if(ssl_wait_for_connection(option.sock, client_fd, &option.ssl, option.ctx) < 0)
			{
				SSL_close_all(option.ssl, option.ctx, client_fd);
				s_log(eINFO, "socket closed and SSL shutdown.\n");

				s_log(eDEBUG1, "calling exit(%i)", EXIT_FAILURE);
				exit(EXIT_FAILURE);
			}

			strncpy(client.cid.cipher, SSL_get_cipher(option.ssl), sizeof(client.cid.cipher) -1);
			s_log(eDEBUG1, "using cipher %.63s", client.cid.cipher);

			s_log(eDEBUG2, "calling ssl_multiplex_loop(%i, %x, %i, %i, %i)", option.ssl, &client, STDIN_FILENO, STDOUT_FILENO, client_fd);
			client.cid.real = 1;
			ssl_multiplex_loop(option.ssl, &client, STDIN_FILENO, STDOUT_FILENO, client_fd);

			fclose(client.cid.session);

			if(create_SHA1(client.cid.file_session, option.strict_inode, option.strict_mode, option.strict_owner, option.strict_ctime, option.strict_mtime))
				strncpy(client.cid.hash_session, create_SHA1(client.cid.file_session, option.strict_inode, option.strict_mode, option.strict_owner, option.strict_ctime, option.strict_mtime), sizeof(client.cid.hash_session));

			sql_client_logoff(&client);

			s_log(eINFO, "session closed for user %.63s@%.100s", client.cid.real_pw_name, client.where);
			SSL_close_all(option.ssl, option.ctx, client_fd);
			s_log(eDEBUG1, "calling exit(%i)", EXIT_SUCCESS);
			exit(EXIT_SUCCESS);
		}

		s_log(eDEBUG1, "calling close(%i)", client_fd);
		close(client_fd);
	}

	ssl_close_connection(option.ssl, option.ctx);
	shutdown(option.sock, SHUT_RDWR);
	close(option.sock);
	if(unlink(option.pidfile) < 0)
		s_log(eERROR, "unlink(%.100s): %.100s (%i)", option.pidfile, strerror(errno), errno);
	exit(EXIT_SUCCESS);
}

int become_daemon1(void)
{
	FILE *f;
	struct flock lock;
	struct stat s;
	char *line, pidbuf[BUFSIZ];

	if(chdir("/") < 0)
	{
		fprintf(stderr, "%.100s (%i)\n", strerror(errno), errno);
		s_log(eERROR, "%.100s (%i)\n", strerror(errno), errno);
		return(-1);
	}

	if(stat(option.pidfile, &s) < 0)
	{
		if((option.lock_fd = open(option.pidfile, O_RDWR|O_CREAT|O_EXCL,0644)) < 0)
		{
			fprintf(stderr, "Couldn't create lock file: %.100s: %.100s (%i)\n", option.pidfile, strerror(errno), errno);
			s_log(eERROR, "Couldn't create lock file: %.100s: %.100s (%i)\n", option.pidfile, strerror(errno), errno);
			return(-1);
		}

		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_len = lock.l_start = 0;
		lock.l_pid = 0;

		if(fcntl(option.lock_fd, F_SETLK, &lock) < 0)
		{
			close(option.lock_fd);
			fprintf(stderr, "Can't lock pidfile: %.100s: %.100s (%i)\n", option.pidfile, strerror(errno), errno);
			s_log(eERROR, "Can't lock pidfile: %.100s: %.100s (%i)\n", option.pidfile, strerror(errno), errno);
			exit(EXIT_FAILURE);
		}

		if(option.uid != -1)
		{
			if(chown(option.pidfile, option.uid, option.gid) < 0)
			{
				fprintf(stderr, "chown(%.100s, %i, %i): %.100s (%i)\n", option.pidfile, option.uid, option.gid, strerror(errno), errno);
				return(-1);
			}
		}
	}
	else
	{
		if((f = fopen(option.pidfile, "r")) == (FILE *) 0)
		{
			fprintf(stderr, "fopen(%.100s): %.100s (%i)\n", option.pidfile, strerror(errno), errno);
			s_log(eERROR, "fopen(%.100s): %.100s (%i)\n", option.pidfile, strerror(errno), errno);
			return(-1);
		}


		if((line = fgets(pidbuf, BUFSIZ - 1, f)) == (char *) 0)
		{
			fprintf(stderr, "Lock file is empty.  This means something else other than easd created or modified this file.  Delete the lock file and try again.\n%.100s\n", option.pidfile);
			s_log(eERROR, "Lock file is empty.  This means something else other than easd created or modified this file.  Delete the lock file and try again.\n%.100s\n", option.pidfile);
			return(-1);
		}

		if(pidbuf[strlen(pidbuf) - 1] == '\n')
			pidbuf[strlen(pidbuf) - 1] = '\0';

		switch(kill(strtoul(pidbuf, (char **) 0, 10), 0))
		{
			case 0:
				fprintf(stderr, "easd[%ld] is already running.  Lock file = %.100s\n", strtoul(pidbuf, (char **) 0, 10), option.pidfile);
				s_log(eERROR, "easd[%ld] is already running.  Lock file = %.100s\n", strtoul(pidbuf, (char **) 0, 10), option.pidfile);
				return(-1);
				break;
			case -1:
				switch(errno)
				{
					case EPERM:
						fprintf(stderr, "easd[%ld] is already running, but you do not have permission to kill it.  Lock file = %.100s\n", strtoul(pidbuf, (char **) 0, 10), option.pidfile);
						s_log(eERROR, "easd[%ld] is already running, but you do not have permission to kill it.  Lock file = %.100s\n", strtoul(pidbuf, (char **) 0, 10), option.pidfile);
						return(-1);
						break;
					default:
						fprintf(stderr, "easd[%ld] is now defunct, but the lock file still exists.  Delete the lock file and try again. \n%.100s\n", strtoul(pidbuf, (char **) 0, 10), option.pidfile);
						s_log(eERROR, "easd[%ld] is now defunct, but the lock file still exists.  Delete the lock file and try again. \n%.100s\n", strtoul(pidbuf, (char **) 0, 10), option.pidfile);
						return(-1);
						break;
				}
				break;
		}

		return(-1);
	}

	return(0);
}

int become_daemon2(void)
{
	char pidbuf[BUFSIZ];

	switch(fork())
	{
		case 0:
			break;
		case -1:
			fprintf(stderr, "fork: %.100s (%i)\n", strerror(errno), errno);
			s_log(eERROR, "fork: %.100s (%i)\n", strerror(errno), errno);
			exit(EXIT_FAILURE);
			break;
		default:
			exit(EXIT_SUCCESS);
			break;
	}

	if(setsid() < 0)
	{
		fprintf(stderr, "setsid: %.100s (%i)\n", strerror(errno), errno);
		s_log(eERROR, "setsid: %.100s (%i)\n", strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	switch(fork())
	{
		case 0:
			break;
		case -1:
			fprintf(stderr, "fork: %.100s (%i)\n", strerror(errno), errno);
			s_log(eERROR, "fork: %.100s (%i)\n", strerror(errno), errno);
			exit(EXIT_FAILURE);
			break;
		default:
			exit(EXIT_SUCCESS);
			break;
	}

	if(ftruncate(option.lock_fd, 0) < 0)
	{
		fprintf(stderr, "ftruncate: %.100s: %.100s (%i)\n", option.pidfile, strerror(errno), errno);
		s_log(eERROR, "ftruncate: %.100s: %.100s (%i)\n", option.pidfile, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	snprintf(pidbuf, BUFSIZ - 1, "%lu\n", (long) getpid());

	if(write(option.lock_fd, pidbuf, strlen(pidbuf)) < 0)
	{
		fprintf(stderr, "write: %.100s: %.100s (%i)\n", option.pidfile, strerror(errno), errno);
		s_log(eERROR, "write: %.100s: %.100s (%i)\n", option.pidfile, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	umask(0);

	if(setsid() < 0)
	{
		fprintf(stderr, "setpgrp: %.100s (%i)\n", strerror(errno), errno);
		s_log(eERROR, "setpgrp: %.100s (%i)\n", strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "r", stdout);
	freopen("/dev/null", "r", stderr);

	return(0);
}

void init_client(struct client_info *c)
{
	memset(c->sysname, '\0', sizeof(c->sysname));
	memset(c->nodename, '\0', sizeof(c->nodename));
	memset(c->release, '\0', sizeof(c->release));
	memset(c->version, '\0', sizeof(c->version));
	memset(c->machine, '\0', sizeof(c->machine));
	memset(c->where, '\0', sizeof(c->where));

	memset(c->cid.real_pw_name, '\0', sizeof(c->cid.real_pw_name));
	memset(c->cid.real_gr_name, '\0', sizeof(c->cid.real_gr_name));
	memset(c->cid.effective_pw_name, '\0', sizeof(c->cid.effective_pw_name));
	memset(c->cid.effective_gr_name, '\0', sizeof(c->cid.effective_gr_name));
	memset(c->cid.original_pw_name, '\0', sizeof(c->cid.original_pw_name));
	memset(c->cid.terminal, '\0', sizeof(c->cid.terminal));
	memset(c->cid.user_string, '\0', sizeof(c->cid.user_string));
	memset(c->cid.dns, '\0', sizeof(c->cid.dns));
	memset(c->cid.ip, '\0', sizeof(c->cid.ip));
	memset(c->cid.remote_command, '\0', sizeof(c->cid.remote_command));
	memset(c->cid.cipher, '\0', sizeof(c->cid.cipher));
	memset(c->cid.method, '\0', sizeof(c->cid.method));
	memset(c->cid.key, '\0', sizeof(c->cid.key));
	memset(c->cid.file_session, '\0', sizeof(c->cid.file_session));
	memset(c->cid.hash_session, '\0', sizeof(c->cid.hash_session));

	c->cid.real_uid = -1;
	c->cid.real_gid = -1;
	c->cid.effective_uid = -1;
	c->cid.effective_gid = -1;
	c->cid.original_uid = -1;
	c->cid.port = -1;
	c->cid.idle = 0;
	c->cid.rowid = -1;
	c->cid.real = 0;
	c->cid.eject = 0;
	c->cid.pid = -1;
	c->cid.pty_session = -1;

	c->cid.session = (FILE *) 0;
}

void sql_client_logoff(struct client_info *c)
{
	sqlite3 *db;
	sqlite3_stmt *statement;

	if(sqlite3_open(option.sessiondb, &db))
	{
		s_log(eERROR, "sqlite3_open: %.100s", sqlite3_errmsg(db));
		return;
	}

	sqlite3_busy_timeout(db, 2000);

	if(sqlite3_prepare(db, "UPDATE USER SET duration=?,status=?,hash_session=? WHERE id=?", -1, &statement, NULL) != SQLITE_OK)
	{
		s_log(eERROR, "sqlite3_prepare: %.100s", sqlite3_errmsg(db));
		return;
	}

	sqlite3_bind_int(statement, 1, duration());
	if(c->cid.eject == 1)
		sqlite3_bind_text(statement, 2, "EJECTED", -1, SQLITE_TRANSIENT);
	else
		sqlite3_bind_text(statement, 2, "COMPLETE", -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(statement, 3, c->cid.hash_session, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int(statement, 4, c->cid.rowid);

	if(sqlite3_step(statement) != SQLITE_DONE)
	{
		s_log(eERROR, "sqlite3_step: %.100s", sqlite3_errmsg(db));
		return;
	}

	sqlite3_finalize(statement);
	sqlite3_close(db);
	return;
}
