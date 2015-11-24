#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "config.h"

#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#include <sys/time.h>
#else                           /* TIME_WITH_SYS_TIME */
#ifdef HAVE_TIME_H
#include <time.h>
#endif                          /* HAVE_TIME_H */
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif                          /* HAVE_SYS_TIME_H */
#endif                          /* TIME_WITH_SYS_TIME */
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
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rand.h"
#include "openssl/sha.h"

#include "client_id.h"
#include "ssl.h"
#include "socket.h"
#include "servconf.h"
#include "log.h"
#include "sig.h"
#include "io.h"

#include "../sqlite/sqlite3.h"

extern volatile sig_atomic_t received_sigusr1;
extern volatile sig_atomic_t received_shutdown;
extern volatile sig_atomic_t received_sigchld;
extern struct ServerOption option;

void _ssl_error(const char *fmt, va_list args)
{
	long e;
	char str[BUFSIZ];

	memset(str, '\0', sizeof(str));
	vsnprintf(str, sizeof(str) - 1, fmt, args);

	fprintf(stderr, "ssl error: %.200s\n", str);

	while((e = ERR_get_error()))
		fprintf(stderr, "ssl error: %.100s\n", ERR_reason_error_string(e));

	return;
}

void ssl_error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	_ssl_error(fmt, args);
	va_end(args);

	return;
}

int ssl_init_accept(SSL_CTX **ctx, SSL_METHOD *method, char *pemfile, char **cafiles, char *cipher)
{
	int x = 0;

	if((*ctx = SSL_CTX_new(method)) == NULL)
	{
		s_log(eERROR, "SSL_CTX_new failed!");
		ssl_error("SSL_CTX_new");
		return(-1);
	}

	if(cipher)
	{
		if(!SSL_CTX_set_cipher_list(*ctx, cipher))
		{
			s_log(eERROR, "SSL_CTX_set_cipher_list(%.100s)", cipher);
			ssl_error("SSL_CTX_set_cipher_list(%.100s)", cipher);
			return(-1);
		}
	}

	if(pemfile == (char *) 0)
	{
		s_log(eERROR, "please specify a private key.");
		ssl_error("please specify a private key.");
		return(-1);
	}

	if(*cafiles == (char *) 0)
	{
		s_log(eERROR, "please specify a CA.");
		ssl_error("please specify a CA.");
		return(-1);
	}

	if(!SSL_CTX_use_PrivateKey_file(*ctx, pemfile, SSL_FILETYPE_PEM))
	{
		s_log(eERROR, "SSL_CTX_use_PrivateKey_file(%.100s)", pemfile);
		ssl_error("SSL_CTX_use_PrivateKey_file(%.100s)", pemfile);
		return(-1);
	}

	if(!SSL_CTX_use_certificate_chain_file(*ctx, pemfile))
	{
		s_log(eERROR, "SSL_CTX_use_certificate_chain_file(%.100s)", pemfile);
		ssl_error("SSL_CTX_use_certificate_chain_file(%.100s)", pemfile);
		return(-1);
	}

	if(!SSL_CTX_load_verify_locations(*ctx, pemfile, NULL))
	{
		s_log(eERROR, "SSL_CTX_load_verify_locations(%.100s)", pemfile);
		ssl_error("SSL_CTX_load_verify_locations(%.100s)", pemfile);
		return(-1);
	}

	for(x = 0; cafiles[x] != (char *) 0; x++)
	{
		if(!SSL_CTX_load_verify_locations(*ctx, cafiles[x], NULL))
		{
			s_log(eERROR, "SSL_CTX_load_verify_locations(%.100s)", pemfile);
			ssl_error("SSL_CTX_load_verify_locations(%.100s)", pemfile);
			return(-1);
		}
	}

	if(!SSL_CTX_check_private_key(*ctx))
	{
		s_log(eERROR, "SSL_CTX_check_private_key(%.100s)", pemfile);
		ssl_error("SSL_CTX_check_private_key(%.100s)", pemfile);
		return (-1);
	}

	SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER, NULL);

	return(0);
}

int ssl_wait_for_connection(int sock_accept, int sock, SSL **ssl_socket, SSL_CTX *ctx)
{
	int i;
	int ssl_accept_ok = 0;
	int oldflags = 0;
	X509 *peer_cert;
	struct timeval timeout;

	if(!(*ssl_socket = SSL_new(ctx)))
	{
		s_log(eERROR, "SSL_new():");
		shutdown(sock, SHUT_RDWR);
		close(sock);
		SSL_free(*ssl_socket);
		return(-1);
	}

	oldflags = set_nonblocking_mode(sock);

	if(!SSL_set_fd(*ssl_socket, sock))
	{
		s_log(eERROR, "SSL_set_fd():");
		shutdown(sock, SHUT_RDWR);
		close(sock);
		SSL_free(*ssl_socket);
		return(-1);
	}

	for(i = 0; i < 25; i++, timeout.tv_sec = 0, timeout.tv_usec = 200000, select(0, (fd_set *) 0, (fd_set *) 0, (fd_set *) 0, &timeout))
	{
		switch(SSL_accept(*ssl_socket))
		{
			case 1:
				i = 999;
				ssl_accept_ok = 1;
				break;
			case -1:
				break;
			default:
				s_log(eERROR, "SSL_accept():");
				shutdown(sock, SHUT_RDWR);
				close(sock);
				SSL_free(*ssl_socket);
				return(-1);
				break;
		}
	}

	if(ssl_accept_ok != 1)
	{
		s_log(eERROR, "connection timed out.");
		return(-1);
	}

	unset_nonblocking_mode(sock, oldflags);

	if(!(peer_cert = SSL_get_peer_certificate(*ssl_socket)))
	{
		shutdown(sock, SHUT_RDWR);
		close(sock);
		SSL_free(*ssl_socket);
		s_log(eERROR, "client did not present a certificate.");
		return(-1);
	}

	s_log(eDEBUG1, "client certificate information:");
	s_log(eDEBUG1, "... subject: %.100s", X509_NAME_oneline(X509_get_subject_name(peer_cert), 0, 0));
	s_log(eDEBUG1, "... issuer: %.100s", X509_NAME_oneline(X509_get_issuer_name(peer_cert), 0, 0));

	return (sock);
}

int ssl_multiplex_loop(SSL *ssl_socket, struct client_info *client, int sockin, int sockprint, int sockout)
{
	int n = 0;
	char buf[32768];
	fd_set rd;

	client->cid.ready = 0;

	while(client->cid.eject == 0 && !received_shutdown)
	{
		/* gather any pending data */
		if(SSL_pending(ssl_socket))
		{
			client->cid.idle = 0;
			memset(buf, '\0', sizeof(buf));
			if(client->cid.ready)
			{
				Header h;

				if((n = ssl_read(ssl_socket, buf, sizeof(buf) - 1)) <= 0)
				{
					s_log(eDEBUG1, "ssl_read: n = %i:", n);
					return(-1);
				}

				h.len = n;
				gettimeofday(&h.tv, NULL);
				write_header(client->cid.session, &h);
				fwrite(buf, 1, n, client->cid.session);

				if(option.sync)
					fflush(client->cid.session);
			}
			else
			{
				if((n = ssl_readline(ssl_socket, buf, sizeof(buf) - 1)) <= 0)
				{
					s_log(eDEBUG1, "ssl_read: n = %i:", n);
					return(-1);
				}

				if(parse_protocol(ssl_socket, client, buf) < 0)
				{
					int fd;

					fd = SSL_get_fd(ssl_socket);
					SSL_shutdown(ssl_socket);
					shutdown(fd, 2);
					close(fd);

					return(-1);
				}
			}
		}

		FD_ZERO(&rd);
		FD_SET(sockout, &rd);

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


		if(select(FD_SETSIZE, &rd, NULL, NULL, NULL) < 0)
		{
			if(errno == EINTR)
				continue;

			s_log(eERROR, "select: %.100s (%i)", strerror(errno), errno);
			return(-1);
		}

		/* read data on the socket */
		if(FD_ISSET(sockout, &rd))
		{
			memset(buf, '\0', sizeof(buf));
			client->cid.idle = 0;

			if(client->cid.ready)
			{
				Header h;

				if((n = ssl_read(ssl_socket, buf, sizeof(buf) - 1)) <= 0)
				{
					s_log(eDEBUG1, "ssl_read: n = %i:", n);
					return(-1);
				}

				h.len = n;
				gettimeofday(&h.tv, NULL);
				write_header(client->cid.session, &h);
				fwrite(buf, 1, n, client->cid.session);

				if(option.sync)
					fflush(client->cid.session);
			}
			else
			{
				if((n = ssl_readline(ssl_socket, buf, sizeof(buf) - 1)) <= 0)
				{
					s_log(eDEBUG1, "ssl_read: n = %i:", n);
					return(-1);
				}

				if(parse_protocol(ssl_socket, client, buf) < 0)
				{
					int fd;

					fd = SSL_get_fd(ssl_socket);
					SSL_shutdown(ssl_socket);
					shutdown(fd, 2);
					close(fd);

					return(-1);
				}
			}
		}
	}

	return(0);
}

int ssl_connect_ip(struct in_addr *ip, unsigned short port, unsigned short sport, SSL **ssl_socket, SSL_CTX **ctx, SSL_METHOD *method, int t, int print)
{
	int sock;
	X509 *peer_cert;

	if((sock = connect_tcp(ip, port, sport, t, print)) == -1)
	{
		/*
		ssl_close_connection(*ssl_socket, *ctx);
		*/
		return (-1);
	}

	if(!(*ssl_socket = SSL_new(*ctx)))
	{
		ssl_error("SSL_new");
		return(-1);
	}

	if(!SSL_set_fd(*ssl_socket, sock))
	{
		ssl_error("SSL_set_fd");
		return(-1);
	}

	if(SSL_connect(*ssl_socket) <= 0)
	{
		ssl_error("SSL_connect");
		SSL_free(*ssl_socket);
		return(-1);
	}

	if(!(peer_cert = SSL_get_peer_certificate(*ssl_socket)))
	{
		ssl_error("server did not present a certificate.");
		return(-1);
	}

#if 0
	if(print)
	{
		fprintf(stderr, "server certificate information:\n");
		fprintf(stderr, "subject: %.100s\n", X509_NAME_oneline(X509_get_subject_name(peer_cert), 0, 0));
		fprintf(stderr, "issuer: %.100s\n", X509_NAME_oneline(X509_get_issuer_name(peer_cert), 0, 0));
	}
#endif

	return (sock);
}

int ssl_close_connection(SSL *ssl_socket, SSL_CTX *ctx)
{
	if(ssl_socket)
	{
		SSL_shutdown(ssl_socket);
		SSL_free(ssl_socket);
	}

	if(ctx)
		SSL_CTX_free(ctx);

	return (0);
}

int ssl_handshake_timeout(SSL *ssl_socket, int socket, int timeout)
{
	int oldflags = 0, ssl_ret;

	SSL_set_fd(ssl_socket, socket);
	SSL_set_connect_state(ssl_socket);

	if((oldflags = set_nonblocking_mode(socket)) < 0)
		return (-1);

	ssl_ret = SSL_do_handshake(ssl_socket);

	if((unset_nonblocking_mode(socket, oldflags)) < 0)
		return (-1);

	if(!SSL_is_init_finished(ssl_socket))
	{
		if(data_available(socket, timeout) < 0)
			return (-1);

		ssl_ret = SSL_connect(ssl_socket);
	}

	switch (ssl_ret)
	{
		default:
		case (-1):
			s_log(eERROR, "TLS/SSL handshake failed.");
			return (-1);
		case (0):
			s_log(eERROR, "TLS/SSL handshake failed cleanly.");
			return (-1);
		case (1):
			return (0);
	}
}

int ssl_close_all(int fd, SSL *ssl_socket, SSL_CTX *ctx)
{
	ssl_close_connection(ssl_socket, ctx);

	if (fd)
		close(fd);

	return(0);
}

void ssl_seed(const char *egdfile, const char *randomfile)
{
	int bytes = 0;

        if(RAND_status() == 0)
        {
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
                if(egdfile != (char *) 0)
                {
                        if((bytes = RAND_egd(egdfile)) < 0)
                        {
                                s_log(eERROR, "EGD socket '%.100s' failed:", egdfile);
                                ssl_error("EGD socket '%.100s' failed:", egdfile);
                                exit(EXIT_FAILURE);
                        }
                }
#ifdef EGD_SOCKET
                if((bytes = RAND_egd(EGD_SOCKET)) < 0)
                {
                        s_log(eERROR, "EGD socket '%.100s' failed:", EGD_SOCKET);
                        ssl_error("EGD socket '%.100s' failed:", EGD_SOCKET);
                        exit(EXIT_FAILURE);
                }
#endif /* EGD_SOCKET */
#endif /* SSLEAY_VERSION_NUMBER */

                if(randomfile != (char *) 0)
                {
                        if((bytes = RAND_load_file(randomfile, 64)) < 0)
                        {
                                s_log(eERROR, "RAND_load_file:");
                                ssl_error("RAND_load_file:");
                                exit(EXIT_FAILURE);
                        }
                }

#ifdef RANDOM_FILE
		if((bytes = RAND_load_file(RANDOM_FILE, 64)) < 0)
		{
			s_log(eERROR, "RAND_load_file:");
			ssl_error("RAND_load_file:");
			exit(EXIT_FAILURE);
		}
#endif

                if(RAND_status() == 0)
                {
                        s_log(eERROR, "RAND_status reported there wasn't enough randomness for the PRNG.");
                        s_log(eERROR, "You need to specify RandomFile or EGDFile to obtain the randomness.");
                        ssl_error("RAND_status reported there wasn't enough randomness for the PRNG.");
                        ssl_error("You need to specify RandomFile or EGDFile to obtain the randomness.");
                        exit(EXIT_FAILURE);
                }
        } /* if(RAND_status() == 0) */
}

size_t my_read(SSL *ssl, char *ptr)
{
	static int read_cnt = 0;
	static char *read_ptr;
	static char read_buf[8192];

	if (read_cnt <= 0)
	{
		memset(read_buf, '\0', sizeof(read_buf));
		if((read_cnt = ssl_read(ssl, read_buf, sizeof(read_buf)-1)) < 0)
			return(-1);
		else if (read_cnt == 0)
			return(0);

		s_log(eINFO, "(%s)", read_buf);
		read_ptr = read_buf;
	}

	read_cnt--;
	*ptr = *read_ptr++;

	return(1);
}

/*
size_t ssl_readline(SSL *ssl, void *vptr, size_t maxlen)
{
	int n, rc;
	char c, *ptr;

	ptr = vptr;

	for (n = 1; n < maxlen; n++)
	{
		if((rc = my_read(ssl, &c)) == 1)
		{
			*ptr++ = c;
			if (c == '\n')
				break;
		}
		else if (rc == 0)
		{
			if (n == 1)
				return(0);
			else
				break;
		}
		else
			return(-1);
	}

	*ptr = 0;
	return(n);
}
*/

size_t ssl_readline(SSL *s,char *buf,size_t len)
{
	int ret;
	char c;
	buf[0]='\0';

	do
	{
		ret = ssl_read(s, &c, 1);

		if(ret==-1)
			return -1;
		else if (ret==0)
			break;

		buf[strlen(buf)+1]='\0';
		buf[strlen(buf)]=c;
	} while (c!='\n' && strlen(buf)<len);

	if (ret!=0)
		buf[strlen(buf)]='\0';

	return strlen(buf);
}

int parse_protocol(SSL *ssl_socket, struct client_info *c, const void *line)
{
	int n = 0;
	char pw_name[BUFSIZ];
	char sysname[BUFSIZ];
	char nodename[BUFSIZ];
	char release[BUFSIZ];
	char version[BUFSIZ];
	char machine[BUFSIZ];
	char buffer[BSIZ];
        char real_pw_name[BUFSIZ];
        char real_gr_name[BUFSIZ];
        char effective_pw_name[BUFSIZ];
        char effective_gr_name[BUFSIZ];
        char original_pw_name[BUFSIZ];
        char original_gr_name[BUFSIZ];
        char terminal[BUFSIZ];
        char type[BUFSIZ];
        char command[BUFSIZ];
        int real_uid;
        int effective_uid;
        int original_uid;
        int real_gid;
        int effective_gid;
        int original_gid;
	static int helo = 0;
	static int user = 0;
        int sqlite_c;

        if(!line)
                return(-1);

	if(strlen(line) < 1)
		return(0);

	memset(pw_name, '\0', sizeof(pw_name));
	memset(sysname, '\0', sizeof(sysname));
	memset(nodename, '\0', sizeof(nodename));
	memset(release, '\0', sizeof(release));
	memset(version, '\0', sizeof(version));
	memset(machine, '\0', sizeof(machine));
	memset(type, '\0', sizeof(type));

	memset(buffer, '\0', sizeof(buffer));

        if((n = sscanf(line, "USER\a%63[^\a]\a%i\a%63[^\a]\a%i\a%63[^\a]\a%i\a%63[^\a]\a%i\a%63[^\a]\a%i\a%63[^\a]\a%i\a%100[^\n]", (char *) &original_pw_name, &original_uid, (char *) &original_gr_name, &original_gid, (char *) &real_pw_name, &real_uid, (char *) &real_gr_name, &real_gid, (char *) &effective_pw_name, &effective_uid, (char *) &effective_gr_name, &effective_gid, (char *) &terminal)) == 13)
	{
		sqlite3 *db;
		sqlite3_stmt *statement;
		struct stat s;
		char tmpdir[BUFSIZ];

		if(helo == 0)
		{
			s_log(eERROR, "client tried send USER data before saying HELO.");
			return(-1);
		}

		user = 1;

		c->cid.ready = 1;

		c->cid.original_uid = original_uid;
		c->cid.original_gid = original_gid;
		strncpy(c->cid.original_pw_name, original_pw_name, sizeof(c->cid.original_pw_name) - 1);
		strncpy(c->cid.original_gr_name, original_gr_name, sizeof(c->cid.original_gr_name) - 1);
		strncpy(c->cid.terminal, terminal, sizeof(c->cid.terminal) - 1);

		c->cid.real_uid = real_uid;
		c->cid.real_gid = real_gid;
		strncpy(c->cid.real_pw_name, real_pw_name, sizeof(c->cid.real_pw_name) - 1);
		strncpy(c->cid.real_gr_name, real_gr_name, sizeof(c->cid.real_gr_name) - 1);

		c->cid.effective_uid = effective_uid;
		c->cid.effective_gid = effective_gid;
		strncpy(c->cid.effective_pw_name, effective_pw_name, sizeof(c->cid.effective_pw_name) - 1);
		strncpy(c->cid.effective_gr_name, effective_gr_name, sizeof(c->cid.effective_gr_name) - 1);


		s_log(eDEBUG1, "%-25s = uid=%i(%.63s) gid=%i(%.64s) terminal=%.100s", "Originally logged on as", c->cid.original_uid, c->cid.original_pw_name, c->cid.original_gid, c->cid.original_gr_name, c->cid.terminal);
		s_log(eDEBUG1, "%-25s = uid=%i(%.63s) gid=%i(%.64s)", "Real ID", c->cid.real_uid, c->cid.real_pw_name, c->cid.real_gid, c->cid.real_gr_name);
		s_log(eDEBUG1, "%-25s = uid=%i(%.63s) gid=%i(%.64s)", "Effective ID", c->cid.effective_uid, c->cid.effective_pw_name, c->cid.effective_gid, c->cid.effective_gr_name);

		s_log(eINFO, "session opened for user %.63s by %.63s@%.100s", c->cid.real_pw_name, c->cid.original_pw_name, c->where);

		if(sqlite3_open(option.sessiondb, &db))
		{
			s_log(eERROR, "sqlite3_open: %.100s", sqlite3_errmsg(db));
			return(-1);
		}

		sqlite3_busy_timeout(db, 2000);

		sqlite_c = 0;

		while(sqlite3_exec(db, "BEGIN IMMEDIATE TRANSACTION;", NULL, NULL, NULL) != SQLITE_OK && sqlite_c++ <= 100)
		{
			s_log(eERROR, "sqlite3_exec - waiting for db (%02i): %.100s", sqlite_c, sqlite3_errmsg(db));
			sleep(2);
		}
		if(sqlite_c == 100)
		{
			s_log(eERROR, "sqlite3_exec: %.100s", sqlite3_errmsg(db));
			sqlite3_close(db);
			return(-1);
		}

		if(sqlite3_prepare(db, "INSERT INTO USER (id,real_uid,real_gid,effective_uid,effective_gid,original_uid,original_gid,port,duration,real_pw_name,real_gr_name,effective_pw_name,effective_gr_name,original_pw_name,original_gr_name,terminal,ip,status,stype,method,cipher,sysname,nodename,release,version,machine,file_session,hash_session,dns,remote_command,pid,created,modified) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);", -1, &statement, NULL) != SQLITE_OK)
		{
			s_log(eERROR, "sqlite3_prepare: %.100s", sqlite3_errmsg(db));
			sqlite3_close(db);
			return(-1);
		}

		/*
		* 1 id
		* 2 real_uid
		* 3 real_gid
		* 4 effective_uid
		* 5 effective_gid
		* 6 original_uid
		* 7 original_gid
		* 8 port
		* 9 duration
		* 10 real_pw_name
		* 11 real_gr_name
		* 12 effective_pw_name
		* 13 effective_gr_name
		* 14 original_pw_name
		* 15 original_gr_name
		* 16 terminal
		* 17 ip
		* 18 status
		* 19 stype
		* 20 method
		* 21 cipher
		* 22 sysname
		* 23 nodename
		* 24 release
		* 25 version
		* 26 machine
		* 27 file_session
		* 28 hash_session
		* 29 dns
		* 30 remote_command
		* 31 pid
		* 32 created
		* 33 modified
		*/

		sqlite3_bind_null(statement, 1);

		sqlite3_bind_int(statement, 2, c->cid.real_uid);
		sqlite3_bind_int(statement, 3, c->cid.real_gid);
		sqlite3_bind_int(statement, 4, c->cid.effective_uid);
		sqlite3_bind_int(statement, 5, c->cid.effective_gid);
		sqlite3_bind_int(statement, 6, c->cid.original_uid);
		sqlite3_bind_int(statement, 7, c->cid.original_gid);
		sqlite3_bind_int(statement, 8, c->cid.port);
		sqlite3_bind_int(statement, 9, 0);

		sqlite3_bind_text(statement, 10, c->cid.real_pw_name, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 11, c->cid.real_gr_name, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 12, c->cid.effective_pw_name, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 13, c->cid.effective_gr_name, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 14, c->cid.original_pw_name, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 15, c->cid.original_gr_name, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 16, c->cid.terminal, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 17, c->cid.ip, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 18, "R", -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 19, c->cid.type, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 20, c->cid.method, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 21, c->cid.cipher, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 22, c->sysname, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 23, c->nodename, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 24, c->release, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 25, c->version, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(statement, 26, c->machine, -1, SQLITE_TRANSIENT);

		sqlite3_bind_null(statement, 27);
		sqlite3_bind_null(statement, 28);
		sqlite3_bind_null(statement, 29);
		sqlite3_bind_text(statement, 30, c->cid.remote_command, -1, SQLITE_TRANSIENT);

		sqlite3_bind_int(statement, 31, getpid());

		sqlite3_bind_null(statement, 32);
		sqlite3_bind_null(statement, 33);

		if(sqlite3_step(statement) != SQLITE_DONE)
		{
			s_log(eERROR, "sqlite3_step: %.100s", sqlite3_errmsg(db));
			sqlite3_close(db);
			return(-1);
		}

		c->cid.rowid = (int) sqlite3_last_insert_rowid(db);

		snprintf(c->cid.file_session, sizeof(c->cid.file_session) - 1, "%.127s/%.31s/%.63s/%.63s-%i", option.sessiondirectory, c->cid.ip, c->cid.original_pw_name, c->cid.effective_pw_name, c->cid.rowid);

		sqlite3_finalize(statement);

		if(sqlite3_prepare(db, "UPDATE USER SET file_session=? WHERE id=?", -1, &statement, NULL) != SQLITE_OK)
		{
			s_log(eERROR, "sqlite3_prepare: %.100s", sqlite3_errmsg(db));
			sqlite3_close(db);
			return(-1);
		}

		sqlite3_bind_text(statement, 1, c->cid.file_session, -1, SQLITE_TRANSIENT);
		sqlite3_bind_int(statement, 2, c->cid.rowid);

		if(sqlite3_step(statement) != SQLITE_DONE)
		{
			s_log(eERROR, "sqlite3_step: %.100s", sqlite3_errmsg(db));
			sqlite3_close(db);
			return(-1);
		}

		sqlite3_finalize(statement);

		if(sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK)
		{
			s_log(eERROR, "sqlite3_exec: %.100s", sqlite3_errmsg(db));
			sqlite3_close(db);
			return(-1);
		}

		sqlite3_close(db);

		memset(tmpdir, '\0', sizeof(tmpdir));
		snprintf(tmpdir, sizeof(tmpdir) - 1, "%.127s/%.31s", option.sessiondirectory, c->cid.ip);

		if(stat(tmpdir, &s) == -1)
		{
			if(mkdir(tmpdir, 0700) < 0)
			{
				s_log(eERROR, "mkdir(%.100s): %.100s (%i)", tmpdir, strerror(errno), errno);
				return(-1);
			}
		}

		memset(tmpdir, '\0', sizeof(tmpdir));
		snprintf(tmpdir, sizeof(tmpdir) - 1, "%.127s/%.31s/%.63s", option.sessiondirectory, c->cid.ip, c->cid.original_pw_name);

		if(stat(tmpdir, &s) == -1)
		{
			if(mkdir(tmpdir, 0700) < 0)
			{
				s_log(eERROR, "mkdir(%.100s): %.100s (%i)", tmpdir, strerror(errno), errno);
				return(-1);
			}
		}

		if((c->cid.session = fopen(c->cid.file_session, "w")) == (FILE *) 0)
		{
			s_log(eERROR, "fopen(%.100s): %.100s (%i)", c->cid.file_session, strerror(errno), errno);
			return(-1);
		}

		if(chmod(c->cid.file_session, 0600) < 0)
		{
			s_log(eERROR, "chmod(%.100s, 0600): %.100s (%i)", c->cid.file_session, strerror(errno), errno);
			return (-1);
		}

		if(option.hook)
		{
                        pid_t hook_pid;
			int timeout = option.hook_timeout * 20;
			int break_out = 0;
                        char *env_list[16];
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
                        char bn[BUFSIZ];
			struct timeval tv;

			/*
			stop_timer();
			signal(SIGCHLD, SIG_IGN);
			*/

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
                        memset(bn, '\0', sizeof(bn));

			memset(bn, '\0', sizeof(bn));
			strncpy(bn, basename(option.hook), sizeof(bn) - 1);

                        snprintf(eash_real_pw_name, sizeof(eash_real_pw_name) - 1,
                                "EASH_REAL_PW_NAME=%.63s", real_pw_name);
                        snprintf(eash_real_gr_name, sizeof(eash_real_gr_name) - 1,
                                "EASH_REAL_GR_NAME=%.63s", real_gr_name);
                        snprintf(eash_effective_pw_name, sizeof(eash_effective_pw_name) - 1,
                                "EASH_EFFECTIVE_PW_NAME=%.63s", effective_pw_name);
                        snprintf(eash_effective_gr_name, sizeof(eash_effective_gr_name) - 1,
                                "EASH_EFFECTIVE_GR_NAME=%.63s", effective_gr_name);
                        snprintf(eash_original_pw_name, sizeof(eash_original_pw_name) - 1,
                                "EASH_ORIGINAL_PW_NAME=%.63s", original_pw_name);
                        snprintf(eash_original_gr_name, sizeof(eash_original_gr_name) - 1,
                                "EASH_ORIGINAL_GR_NAME=%.63s", original_gr_name);

                        snprintf(eash_terminal, sizeof(eash_terminal) - 1,
                                "EASH_TERMINAL=%.127s", terminal);
                        snprintf(eash_ip, sizeof(eash_ip) - 1,
                                "EASH_IP=%.127s", c->cid.ip);
                        snprintf(eash_id, sizeof(eash_id) - 1,
                                "EASH_ID=%i", c->cid.rowid);
                        snprintf(eash_command, sizeof(eash_command) - 1,
                                "EASH_COMMAND=%.900s", c->cid.remote_command);

                        snprintf(eash_real_uid, sizeof(eash_real_uid) - 1,
                                "EASH_REAL_UID=%i", real_uid);
                        snprintf(eash_effective_uid, sizeof(eash_effective_uid) - 1,
                                "EASH_EFFECTIVE_UID=%i", effective_uid);
                        snprintf(eash_original_uid, sizeof(eash_original_uid) - 1,
                                "EASH_ORIGINAL_UID=%i", original_uid);
                        snprintf(eash_real_gid, sizeof(eash_real_gid) - 1,
                                "EASH_REAL_GID=%i", real_gid);
                        snprintf(eash_effective_gid, sizeof(eash_effective_gid) - 1,
                                "EASH_EFFECTIVE_GID=%i", effective_gid);
                        snprintf(eash_original_gid, sizeof(eash_original_gid) - 1,
                                "EASH_ORIGINAL_GID=%i", original_gid);

                        env_list[0] = eash_real_pw_name;
                        env_list[1] = eash_real_gr_name;
                        env_list[2] = eash_effective_pw_name;
                        env_list[3] = eash_effective_gr_name;
                        env_list[4] = eash_original_pw_name;
                        env_list[5] = eash_original_gr_name;
                        env_list[6] = eash_terminal;
                        env_list[7] = eash_ip;
                        env_list[8] = eash_real_uid;
                        env_list[9] = eash_effective_uid;
                        env_list[10] = eash_original_uid;
                        env_list[11] = eash_real_gid;
                        env_list[12] = eash_effective_gid;
                        env_list[13] = eash_original_gid;
                        env_list[14] = eash_id;
                        env_list[15] = eash_command;
                        env_list[16] = 0;

                        hook_pid = fork();

                        if(hook_pid == 0)
                        {
				tv.tv_sec = 0;
				tv.tv_usec = 100000;
				select(0, (fd_set *) 0, (fd_set *) 0,(fd_set *) 0, &tv);

				execle(option.hook, bn, (char *) 0, env_list);
				s_log(eERROR, "execle(%.127s, %.63s): %.100s (%i)", option.hook, bn, strerror(errno), errno);
				return(-1);
			}

			received_sigchld = -1;

			while(!break_out && timeout != 0)
			{
				switch(received_sigchld)
				{
					case -1:
						tv.tv_sec = 0;
						tv.tv_usec = 50000;
						select(0, (fd_set *) 0, (fd_set *) 0,(fd_set *) 0, &tv);

						timeout--;
						break;
					case 0:
						s_log(eDEBUG1, "accepted %.63s@%.63s - hook returned zero", c->cid.original_pw_name, c->where);
						ssl_write(ssl_socket, "OK\n", strlen("OK\n"));
						break_out = 1;
						break;
					default:
						s_log(eERROR, "denied %.63s@%.63s - hook returned non-zero", c->cid.original_pw_name, c->where);
						ssl_write(ssl_socket, "DENY HOOK\n", strlen("DENY HOOK\n"));
						break_out = 1;
						break;
				}
			}

			if(timeout == 0)
			{
				s_log(eERROR, "denied %.63s@%.63s - hook timed out after %i seconds.", c->cid.original_pw_name, c->where, option.hook_timeout);
				ssl_write(ssl_socket, "DENY TIMEOUT\n", strlen("DENY TIMEOUT\n"));
			}
		}
		else
		{
			/* don't need authentication from hook - grant it */
			s_log(eDEBUG1, "accepted %.63s@%.63s - no hook", c->cid.original_pw_name, c->where);
			ssl_write(ssl_socket, "OK\n", strlen("OK\n"));
		}

		return(0);
	}
        else if((n = sscanf(line, "HELO\a%63[^\a]\a%100[^\a]\a%100[^\a]\a%100[^\a]\a%100[^\a]\a%100[^\a]\a%900[^\n]", (char *) &type, (char *) &sysname, (char *) &nodename, (char *) &release, (char *) &version, (char *) &machine, (char *) &command)) == 7)
	{
		char *types[] = { "SESSION", "LOGIN", "COMMAND", (char *) 0 };
		int found = 0;
		int i;

		helo = 1;

		strncpy(c->cid.type, type, sizeof(c->cid.type) - 1);
		strncpy(c->sysname, sysname, sizeof(c->sysname) - 1);
		strncpy(c->nodename, nodename, sizeof(c->nodename) - 1);
		strncpy(c->release, release, sizeof(c->release) - 1);
		strncpy(c->version, version, sizeof(c->version) - 1);
		strncpy(c->machine, machine, sizeof(c->machine) - 1);
		strncpy(c->cid.remote_command, command, sizeof(c->cid.remote_command) - 1);

		for(i = 0; types[i]; i++)
			if(!strcmp(c->cid.type, types[i]))
				found = 1;

		if(!found)
		{
			s_log(eERROR, "UNKNOWN TYPE '%.63s'", c->cid.type);
			return(-1);
		}

		return(0);
	}
	else
	{
		s_log(eERROR, "UNKNOWN PROTOCOL: '%s'", (char *) line);
		return(-1);
	}

        return(-1);
}

int ssl_timeout(int sock, unsigned secs, unsigned usecs)
{
	struct timeval timeout;
	fd_set fd;

	FD_ZERO(&fd);
	FD_SET(sock, &fd);

	timeout.tv_sec = secs;
	timeout.tv_usec = usecs;

	return select(sock+1, NULL, &fd, NULL, &timeout);
}

size_t ssl_write(SSL *ssl, void *buf, size_t len)
{
	int rc;
	unsigned long err;
	char errmsg[BUFSIZ];

	rc = SSL_write(ssl, buf, len);

	if(rc <= 0)
	{
		int fd;
		int ret;

		ret = SSL_get_error(ssl, rc);
		rc = -1;

		ssl_error("ssl_write");

		if((fd = SSL_get_fd(ssl)) < 0)
			return -1;

		switch(ret)
		{
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				ret = ssl_timeout(fd, 5, 0);

				if(ret == 0)
					return -1;
				else if(ret > 0)
					return ssl_write(ssl, buf, len);
				else
					return -1;

				break;
			default:
				while((err = ERR_get_error()))
					fputs(ERR_error_string(err, errmsg), stderr);

				return -1;
				break;
		}
	}
	else
	{
		return rc;
	}
}

size_t ssl_read(SSL *ssl, void *buf, size_t len)
{
	int rc;
	unsigned long err;
	char errmsg[BUFSIZ];

	rc = SSL_read(ssl, buf, len);

	if(rc <= 0)
	{
		int fd;
		int ret;

		ret = SSL_get_error(ssl, rc);
		rc = -1;

		if((fd = SSL_get_fd(ssl)) < 0)
			return -1;

		switch(ret)
		{
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				ret = ssl_timeout(fd, 5, 0);

				if(ret == 0)
					return -1;
				else if(ret > 0)
					return ssl_read(ssl, buf, len);
				else
					return -1;

				break;
			default:
				while((err = ERR_get_error()))
					s_log(eERROR, ERR_error_string(err, errmsg));

				return -1;
				break;
		}
	}
	else
	{
		return rc;
	}
}

void SSL_close_all(SSL *ssl, SSL_CTX *ctx, int client_fd)
{
	s_log(eDEBUG1, "calling shutdown(%i, SHUT_RDWR)", client_fd);
	if(shutdown(client_fd, SHUT_RDWR) < 0)
	{
		s_log(eERROR, "shutdown(%i, SHUT_RDWR): %.100s (%i)", client_fd, strerror(errno), errno);
		s_log(eDEBUG1, "calling exit(%i)", EXIT_FAILURE);
		exit(EXIT_FAILURE);
	}

	s_log(eDEBUG1, "calling close(%i)", client_fd);
	if(close(client_fd) < 0)
	{
		s_log(eERROR, "close(%i): %.100s (%i)", client_fd, strerror(errno), errno);
		s_log(eDEBUG1, "calling exit(%i)", EXIT_FAILURE);
		exit(EXIT_FAILURE);
	}

	s_log(eDEBUG2, "calling SSL_shutdown(%x)", ssl);
	if(SSL_shutdown(ssl) < 0)
	{
		s_log(eERROR, "SSL_shutdown: %.100s (%i)", strerror(errno), errno);
		s_log(eDEBUG1, "calling exit(%i)", EXIT_FAILURE);
		exit(EXIT_FAILURE);
	}

	s_log(eDEBUG2, "calling SSL_free(%x)", ssl);
	SSL_free(ssl);

	s_log(eDEBUG2, "calling SSL_CTX_free(%x)", ctx);
	SSL_CTX_free(ctx);
}

char *create_SHA1(const char *file, int strict_inode, int strict_mode, int strict_owner, int strict_ctime, int strict_mtime)
{
	SHA_CTX c;
	static unsigned char md[SHA_DIGEST_LENGTH];
	static unsigned char buf[8192];
	static char ret_buf[8192];
	static char tmp[BUFSIZ];
	struct stat s;
	char *ptr = ret_buf;
	int fd;
	int i;
	FILE *f;

	memset(ret_buf, '\0', sizeof(ret_buf));
	memset(md, '\0', sizeof(md));
	memset(buf, '\0', sizeof(buf));

	if((f = fopen(file, "r")) == (FILE *) 0)
	{
		if(isatty(STDERR_FILENO))
			fprintf(stderr, "fopen(%.100s): %.100s (%i)", file, strerror(errno), errno);

		s_log(eERROR, "fopen(%.100s): %.100s (%i)", file, strerror(errno), errno);
		return(0);
	}

	fd = fileno(f);
	SHA1_Init(&c);

	for(;;)
	{
		i = read(fd, buf, sizeof(buf) - 1);

		if(i <= 0)
			break;

		SHA1_Update(&c, buf, (unsigned long) i);
	}

	if(stat(file, &s) == -1)
	{
		fprintf(stderr, "stat: %.100s: %.100s (%i)\n", file, strerror(errno), errno);
		return(0);
	}

	if(strict_inode)
	{
		memset(tmp, '\0', sizeof(tmp));
		snprintf(tmp, sizeof(tmp) - 1, "%ld", s.st_ino);
		SHA1_Update(&c, tmp, strlen(tmp));
	}
	if(strict_mode)
	{
		memset(tmp, '\0', sizeof(tmp));
		snprintf(tmp, sizeof(tmp) - 1, "%i", s.st_mode);
		SHA1_Update(&c, tmp, strlen(tmp));
	}
	if(strict_owner)
	{
		memset(tmp, '\0', sizeof(tmp));
		snprintf(tmp, sizeof(tmp) - 1, "%i:%i", s.st_uid, s.st_gid);
		SHA1_Update(&c, tmp, strlen(tmp));
	}
	if(strict_ctime)
	{
		memset(tmp, '\0', sizeof(tmp));
		snprintf(tmp, sizeof(tmp) - 1, "%ld", s.st_ctime);
		SHA1_Update(&c, tmp, strlen(tmp));
	}
	if(strict_mtime)
	{
		memset(tmp, '\0', sizeof(tmp));
		snprintf(tmp, sizeof(tmp) - 1, "%ld", s.st_mtime);
		SHA1_Update(&c, tmp, strlen(tmp));
	}

	SHA1_Final(&(md[0]),&c);

	for(i = 0; i < SHA_DIGEST_LENGTH; i++)
	{
		ptr[i*2+0] = "0123456789abcdef"[(md[i] >> 4) & 0x0f];
		ptr[i*2+1] = "0123456789abcdef"[(md[i] >> 0) & 0x0f];
	}

	s_log(eDEBUG1, "SHA1(%.100s)= %.100s", file, ptr);

	ptr[sizeof(ret_buf)] = 0;

	fclose(f);
	close(fd);

	return ptr;
}
