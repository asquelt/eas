#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

#include "client_id.h"
#include "ssl.h"
#include "socket.h"
#include "sig.h"
#include "servconf.h"
#include "log.h"
#include "random.h"
#include "sql.h"
#include "funcs.h"
#include "vd.h"
#include "io.h"

#include "../sqlite/sqlite3.h"

typedef double (*wait_func) (struct timeval, struct timeval, double);
typedef int (*read_func) (FILE *, Header *, char **);
typedef void (*write_func) (char *, int);
typedef void (*proccess_func) (FILE *, double, read_func, wait_func);

/* function declaration */
int replay(unsigned int);
int playback(const char *, const char *);
void stop_playback(void);

/* globals */
struct ServerOption option;
struct client_info client;
char **saved_argv;
char progname[BUFSIZ];
struct termios old, new;
double speed, maxwait;
read_func read_function;
wait_func wait_function;
proccess_func process_function;

struct timeval timeval_diff(struct timeval tv1, struct timeval tv2)
{
	struct timeval diff;

	diff.tv_sec = tv2.tv_sec - tv1.tv_sec;
	diff.tv_usec = tv2.tv_usec - tv1.tv_usec;

	if(diff.tv_usec < 0)
	{
		diff.tv_sec--;
		diff.tv_usec += 1000000;
	}

	return diff;
}

struct timeval timeval_div(struct timeval tv1, double n)
{
	double x = ((double) tv1.tv_sec  + (double) tv1.tv_usec / 1000000.0) / n;
	struct timeval div;

	div.tv_sec  = (int) x;
	div.tv_usec = (x - (int) x) * 1000000;

	return div;
}

double eash_ttywait(struct timeval prev, struct timeval cur, double speed)
{
	struct timeval diff = timeval_diff(prev, cur);
	fd_set readfs;

	if(speed == 0)
	{
		fprintf(stderr, "%.63s: speed cannot be 0.\n", basename(progname));
		exit(EXIT_FAILURE);
	}

	diff = timeval_div(diff, speed);

	if(diff.tv_usec < 100000)
		diff.tv_usec = 0;

	if(maxwait > 0 && diff.tv_sec > maxwait)
	{
		diff.tv_sec = maxwait;
		diff.tv_usec = 0;
	}

	FD_ZERO(&readfs);
	FD_SET(STDIN_FILENO, &readfs);
	
	select(1, &readfs, (fd_set *) 0, (fd_set *) 0, &diff);

	if(FD_ISSET(STDIN_FILENO, &readfs))
	{
		char c;
		int n;

		if((n = read(STDIN_FILENO, &c, 1)) <= 0)
		{
			if(n == 0)
				stop_playback();

			fprintf(stderr, "read(%i): %.100s (%i)\n", STDIN_FILENO, strerror(errno), errno);
			exit(EXIT_FAILURE);
		}

		switch(c)
		{
			case '+':
			case '=':
			case 'f':
			case 'a':
				speed *= 2;
				break;
			case '-':
			case '_':
			case 's':
			case 'z':
				speed /= 2;
				break;
			case '1':
			case 'r':
				speed = 1;
				break;
			case 'x':
			case 'q':
				stop_playback();
				break;
		}
	}

	return speed;
}

double eash_ttynowait(struct timeval prev, struct timeval cur, double speed)
{
	return(0);
}

int eash_ttyread(FILE *fp, Header *h, char **buf)
{
	if(read_header(fp, h) == 0)
		return(0);

	if(h->len > 0)
		*buf = (char *) malloc(h->len);
	else
	{
		fprintf(stderr, "%.63s: file is corrupted - cannot read lengh: %i\n", basename(progname), h->len);
		exit(EXIT_FAILURE);
	}

	if(*buf == (char *) 0)
	{
		fprintf(stderr, "%.63s: malloc(%i): %.100s (%i)\n", basename(progname), h->len, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	if(fread(*buf, 1, h->len, fp) == 0)
	{
		fprintf(stderr, "%.63s: fread: %.100s (%i)\n", basename(progname), strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	return(1);
}

int eash_ttypread(FILE *fp, Header *h, char **buf)
{
	while(eash_ttyread(fp, h, buf) == 0)
	{
		struct timeval tv = { 0, 100000 };

		select(0, (fd_set *) 0, (fd_set *) 0, (fd_set *) 0, &tv);
		clearerr(fp);
	}

	return(1);
}

void eash_ttywrite(char *buf, int len)
{
	fwrite(buf, 1, len, stdout);
}

void eash_ttynowrite(char *buf, int len)
{
}

void eash_ttyplay(FILE *fp, double speed, read_func read_function, write_func write_function, wait_func wait_function)
{
	int first_time = 1;
	struct timeval prev;

	setvbuf(stdout, NULL, _IONBF, STDOUT_FILENO);
	setvbuf(fp, NULL, _IONBF, STDOUT_FILENO);

	while(1)
	{
		char *buf;
		Header h;

		if(read_function(fp, &h, &buf) == 0)
			break;

		if(!first_time)
			speed = wait_function(prev, h.tv, speed);

		first_time = 0;

		write_function(buf, h.len);

		prev = h.tv;
		free(buf);
	}
}

void eash_ttyskipall(FILE *fp)
{
	eash_ttyplay(fp, 0, eash_ttyread, eash_ttynowrite, eash_ttynowait);
}

void eash_ttyplayback(FILE *fp, double speed, read_func read_function, wait_func wait_function)
{
	eash_ttyplay(fp, speed, read_function, eash_ttywrite, wait_function);
}

void eash_ttypeek(FILE *fp, double speed, read_func read_function, wait_func wait_function)
{
	eash_ttyskipall(fp);
	eash_ttyplay(fp, speed, eash_ttypread, eash_ttywrite, eash_ttynowait);
}

int main(int argc, char **argv)
{
	extern int optind;
	int c = 0;
	int all = 0;
	int group = 0;
	int reverse = 0;
	int running = 0;
	int rows = 0;
	int sessions = 0;
	int unknowns = 0;
	int commands = 0;
	int active = 0;
	int logins = 0;
	int col = 0;
	int limit = -1;
	char select[4096];
	char *ip = (char *) 0;
	char *from = (char *) 0;
	char *to = (char *) 0;
	sqlite3 *db;
	sqlite3_stmt *statement;

	memset(select, '\0', sizeof(select));
	strncpy(progname, argv[0], sizeof(progname) - 1);

	init_options();

	if(load_config(EASHD_CONFIG) < 0)
		exit(EXIT_FAILURE);

	if(sql_init_db(option.sessiondb) < 0)
		exit(EXIT_FAILURE);

	speed = 1.0;
	maxwait = 0;

	while((c = getopt(argc, argv, "ad:f:g?hi:l:nt:srw:vV")) != EOF)
	{
		switch(c)
		{
			case 'a':
				all = 1;
				break;
			case 'd':
				sscanf(optarg, "%lf", &speed);
				break;
			case 'f':
				from = strdup(optarg);
				break;
			case 'g':
				group = 1;
				break;
			case 'i':
				ip = strdup(optarg);
				break;
			case 'h':
			case '?':
				fprintf(stdout, "Usage: %.63s [-a] [-d speed] [-f from] [-gh] [-i IP] [-l limit] [-ns] [-t to] [-r] [-w maxwait] [-v] [ID]\n", basename(progname));
				fprintf(stdout, "Enterprise Audit Shell Replay\n\n");
				fprintf(stdout, " -a\tshow all sessions.\n");
				fprintf(stdout, " -d\tspeed to playback - default is 1.0.\n");
				fprintf(stdout, " -f\tlimit records by the 'From' field.  E.g. `%.63s -f root'\n", basename(progname));
				fprintf(stdout, " -g\tgroup by username.\n");
				fprintf(stdout, " -h\tdisplay this help synopsis.\n");
				fprintf(stdout, " -i\tlimit records by the 'IP' field.  E.g. `%.63s -i 127.0.0.1'\n", basename(progname));
				fprintf(stdout, " -l\tlimit the number of records in general. E.g. `%.63s -l 10'\n", basename(progname));
				fprintf(stdout, " -n\tno wait - dump session to stdout.\n");
				fprintf(stdout, " -s\tsnoop on a session.\n");
				fprintf(stdout, " -t\tlimit records by the 'To' field.  E.g. `%.63s -t root'\n", basename(progname));
				fprintf(stdout, " -r\treverse sort.\n");
				fprintf(stdout, " -w\tset the maximum amount of time you wish to wait.\n");
				fprintf(stdout, " -v\tdisplay version information.\n");
				exit(EXIT_SUCCESS);
				break;
			case 'n':
				wait_function = eash_ttynowait;
				break;
			case 'l':
				limit = atoi(optarg);
				break;
			case 't':
				to = strdup(optarg);
				break;
			case 'r':
				reverse = 1;
				break;
			case 's':
				process_function = eash_ttypeek;
				break;
			case 'w':
				sscanf(optarg, "%lf", &maxwait);
				break;
			case 'v':
			case 'V':
				print_version(&option, *argv);
				exit(EXIT_SUCCESS);
				break;
			default:
				fprintf(stderr, "Try `%.63s -h' for more information.\n", basename(progname));
				exit(EXIT_FAILURE);
				break;
		}
	}

	argc -= optind;
	argv += optind;

	/* if we still have an arguement go ahead and convert it to a long and replay the session */
	if(*argv != (char *) 0)
	{
		switch(argc)
		{
			case 1:
				if(replay(atoi(*argv)))
					exit(EXIT_FAILURE);
				else
					exit(EXIT_SUCCESS);
				break;
			default:
				fprintf(stderr, "%.63s: too many arguements.\n", basename(progname));
				fprintf(stderr, "Try `%.63s -h' for more information.\n", basename(progname));
				exit(EXIT_FAILURE);
				break;
		}
	}

	if(sqlite3_open(option.sessiondb, &db))
	{
		fprintf(stderr, "sqlite3_open: %.100s", sqlite3_errmsg(db));
		exit(EXIT_FAILURE);
	}

	snprintf(select, sizeof(select) - 1,
		"SELECT created,real_pw_name,original_pw_name,ip,id,stype,status FROM USER WHERE 1=1 %.63s%.63s%.63s%.63s LIMIT ?;",
		ip ? "AND ip=? " : "",
		from ? "AND original_pw_name=? " : "",
		to ? "AND real_pw_name=? " : "",
		group ? 
			reverse ? 
				"ORDER BY original_pw_name DESC,created DESC,ip " : "ORDER BY original_pw_name ASC,created ASC,ip "
			:
			reverse ? 
				"ORDER BY created DESC,original_pw_name,ip " : "ORDER BY created ASC,original_pw_name,ip ");

	sqlite3_busy_timeout(db, 2000);

	if(sqlite3_prepare(db, select, -1, &statement, NULL) != SQLITE_OK)
	{
		fprintf(stderr, "sqlite3_prepare: %.100s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(EXIT_FAILURE);
	}

	col = 1;

	if(ip)
		sqlite3_bind_text(statement, col++, ip, -1, SQLITE_TRANSIENT);
	if(from)
		sqlite3_bind_text(statement, col++, from, -1, SQLITE_TRANSIENT);
	if(to)
		sqlite3_bind_text(statement, col++, to, -1, SQLITE_TRANSIENT);

	sqlite3_bind_int(statement, col++, limit);

			/*          1    1    2    2    3    3    4    4    5    5    6    6    7    7 7 */
			/* 1---5----0----5----0----5----0----5----0----5----0----5----0----5----0----5-7 */
			/* ============================================================================= */
			/* 2005-09-26 02:22:36|dhanks         |root           |255.255.255.255|        1 */
			/* %19s %12s %12s %15s %c %15i */
	/*
	fprintf(stderr, "         1    1    2    2    3    3    4    4    5    5    6    6    7    7 7\n");
	fprintf(stderr, "1---5----0----5----0----5----0----5----0----5----0----5----0----5----0----5-7\n");
	*/
	fprintf(stderr, "=============================================================================\n");
	fprintf(stderr, "%-19s %-15s %-15s %-15s %-4s %4s\n",
		group ?
			reverse ? "Date (s2\\/)" : "Date (s2/\\)"
			:
			reverse ? "Date (s1\\/)" : "Date (s1/\\)",
		group ?
			reverse ? "From (s1\\/)" : "From (s1/\\)"
			:
			reverse ? "From (s2\\/)" : "From (s2/\\)",
		"To", "IP", "Type", "ID");
	fprintf(stderr, "%-19s %-15s %-15s %-15s %-4s %4s\n", "===================", "===============", "===============", "===============", "====", "====");

	running = 1;

	while(running)
	{
		switch(sqlite3_step(statement))
		{
			case SQLITE_DONE:
				running = 0;
				break;
			case SQLITE_ROW:
				rows++;
				/*
				 * 0 created
				 * 1 real_pw_name
				 * 2 original_pw_name
				 * 3 ip
				 * 4 id
				 * 5 type
				*/

				memset(client.cid.created, '\0', sizeof(client.cid.created));
				memset(client.cid.real_pw_name, '\0', sizeof(client.cid.real_pw_name));
				memset(client.cid.original_pw_name, '\0', sizeof(client.cid.original_pw_name));
				memset(client.cid.ip, '\0', sizeof(client.cid.ip));
				memset(client.cid.type, '\0', sizeof(client.cid.type));
				memset(client.cid.status, '\0', sizeof(client.cid.status));

				if(sqlite3_column_text(statement, 0))
					strncpy(client.cid.created, (char *) sqlite3_column_text(statement, 0),
						sizeof(client.cid.created) - 1);
				if(sqlite3_column_text(statement, 1))
					strncpy(client.cid.real_pw_name, (char *) sqlite3_column_text(statement, 1),
						sizeof(client.cid.real_pw_name) - 1);
				if(sqlite3_column_text(statement, 2))
					strncpy(client.cid.original_pw_name, (char *) sqlite3_column_text(statement, 2),
						sizeof(client.cid.original_pw_name) - 1);
				if(sqlite3_column_text(statement, 3))
					strncpy(client.cid.ip, (char *) sqlite3_column_text(statement, 3),
						sizeof(client.cid.ip) - 1);

				client.cid.rowid = sqlite3_column_int(statement, 4);

				if(sqlite3_column_text(statement, 5))
					strncpy(client.cid.type, (char *) sqlite3_column_text(statement, 5),
						sizeof(client.cid.type) - 1);
				if(sqlite3_column_text(statement, 6))
					strncpy(client.cid.status, (char *) sqlite3_column_text(statement, 6),
						sizeof(client.cid.status) - 1);

				if(!strcmp(client.cid.status, "R"))
				{
					active++;
					fprintf(stdout, "%-19s %-15s %-15s %-15s R %7i\n", client.cid.created, client.cid.original_pw_name, client.cid.real_pw_name, client.cid.ip, client.cid.rowid);
				}
				else if(!strcmp(client.cid.type, "COMMAND"))
				{
					commands++;
					fprintf(stdout, "%-19s %-15s %-15s %-15s C %7i\n", client.cid.created, client.cid.original_pw_name, client.cid.real_pw_name, client.cid.ip, client.cid.rowid);
				}
				else if(!strcmp(client.cid.type, "LOGIN"))
				{
					logins++;
					fprintf(stdout, "%-19s %-15s %-15s %-15s L %7i\n", client.cid.created, client.cid.original_pw_name, client.cid.real_pw_name, client.cid.ip, client.cid.rowid);
				}
				else if(!strcmp(client.cid.type, "SESSION"))
				{
					sessions++;
					fprintf(stdout, "%-19s %-15s %-15s %-15s S %7i\n", client.cid.created, client.cid.original_pw_name, client.cid.real_pw_name, client.cid.ip, client.cid.rowid);
				}
				else
				{
					unknowns++;
					fprintf(stdout, "%-19s %-15s %-15s %-15s U %7i\n", client.cid.created, client.cid.original_pw_name, client.cid.real_pw_name, client.cid.ip, client.cid.rowid);
				}
				break;
			default:
				running = 0;
				fprintf(stderr, "sqlite3_step: %.100s\n", sqlite3_errmsg(db));
				break;
		}
	}

	sqlite3_finalize(statement);
	sqlite3_close(db);

	if(rows == 0)
		fprintf(stderr, "No sessions have been recorded.\n");

	fprintf(stderr, "=============================================================================\n");
	if(active)
		fprintf(stderr, "Active: %i\n", active);
	if(sessions)
		fprintf(stderr, "Sessions: %i\n", sessions);
	if(commands)
		fprintf(stderr, "Commands: %i\n", commands);
	if(unknowns)
		fprintf(stderr, "Unknown: %i\n", unknowns);
	if(logins + sessions + commands + unknowns)
		fprintf(stderr, "Total: %i\n", active + logins + sessions + commands + unknowns);
	fprintf(stderr, "=============================================================================\n");
	fprintf(stderr, "Playback usage: %.63s ID [MULTIPLIER] [MAXWAIT]\n", basename(*(argv - optind)));
	fprintf(stderr, "Note: if you replay an active (R) session, snoop-mode will be enabled.\n");
	if(rows)
		fprintf(stderr, "Example: %.63s %i\n",  basename(progname), client.cid.rowid);
	fprintf(stderr, "=============================================================================\n");
	exit(EXIT_SUCCESS);
}

int replay(unsigned int id)
{
	sqlite3 *db;
	sqlite3_stmt *statement;
	int found = 0;

	if(sqlite3_open(option.sessiondb, &db))
	{
		fprintf(stderr, "sqlite3_open: %.100s", sqlite3_errmsg(db));
		return(-1);
	}

	sqlite3_busy_timeout(db, 2000);

	if(sqlite3_prepare(db, "SELECT file_session,hash_session,id,status FROM USER WHERE id=?", -1, &statement, NULL) != SQLITE_OK)
	{
		fprintf(stderr, "sqlite3_open: %.100s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return(-1);
	}

	sqlite3_bind_int(statement, 1, id);

	switch(sqlite3_step(statement))
	{
		case SQLITE_DONE:
			if(!found)
			{
				fprintf(stderr, "%.63s: could not find a session with the ID of %u.\n", basename(progname), id);
				fprintf(stderr, "See `%.63s -a' for a complete list.\n", basename(progname));
				sqlite3_finalize(statement);
				sqlite3_close(db);
				return(-1);
			}
			break;
		case SQLITE_ROW:
			/*
			 * 0 file_session
			 * 1 hash_session
			 * 2 id
			*/
			memset(client.cid.file_session, '\0', sizeof(client.cid.file_session));
			memset(client.cid.hash_session, '\0', sizeof(client.cid.hash_session));
			memset(client.cid.status, '\0', sizeof(client.cid.status));

			if(sqlite3_column_text(statement, 0))
				strncpy(client.cid.file_session, (char *) sqlite3_column_text(statement, 0),
					sizeof(client.cid.file_session) - 1);
			if(sqlite3_column_text(statement, 1))
				strncpy(client.cid.hash_session, (char *) sqlite3_column_text(statement, 1),
					sizeof(client.cid.hash_session) - 1);

			client.cid.rowid = sqlite3_column_int(statement, 2);

			if(sqlite3_column_text(statement, 3))
				strncpy(client.cid.status, (char *) sqlite3_column_text(statement, 3),
					sizeof(client.cid.status) - 1);

			if(!strcmp(client.cid.status, "R"))
				process_function = eash_ttypeek;
			break;
		default:
			fprintf(stderr, "sqlite3_step: %.100s\n", sqlite3_errmsg(db));
			sqlite3_finalize(statement);
			sqlite3_close(db);
			return(-1);
			break;
	}

	sqlite3_finalize(statement);
	sqlite3_close(db);

	return playback(client.cid.file_session, client.cid.hash_session);
}

int playback(const char *file_session, const char *hash_session)
{
	char a[BUFSIZ];
	FILE *input;

	read_function = eash_ttyread;

	if(wait_function != eash_ttynowait)
		wait_function = eash_ttywait;

	if(process_function != eash_ttypeek)
	{
		process_function = eash_ttyplayback;

		if(create_SHA1(file_session, option.strict_inode, option.strict_mode, option.strict_owner, option.strict_ctime, option.strict_mtime))
			strncpy(a, create_SHA1(file_session, option.strict_inode, option.strict_mode, option.strict_owner, option.strict_ctime, option.strict_mtime), sizeof(a) - 1);

		if(strcmp(a, hash_session))
		{
			fprintf(stderr, "%.63s: audit log has been breached.\n", basename(progname));
			fprintf(stderr, "original SHA1: %.63s\n", hash_session);
			fprintf(stderr, "new SHA1: %.63s\n", a);

			return(1);
		}
	}

	if(process_function == eash_ttypeek && option.sync != _IOFBF)
	{
		fprintf(stderr, "%.63s: Sync needs to be set to _IOFBF in order to snoop on running sessions (not recommended).\n", basename(progname));
		exit(EXIT_FAILURE);
	}

	if((input = fopen(file_session, "r")) == (FILE *) 0)
	{
		fprintf(stderr, "%.63s: %.100s: %.100s (%i)\n", basename(progname), file_session, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	/* get terminal attributes */
	tcgetattr(STDIN_FILENO, &old);

#ifdef HAVE_CFMAKERAW
	new= old;
	cfmakeraw(&new);
#endif

	new.c_cc[VEOF] = 1;
	new.c_iflag = BRKINT | ISTRIP | IXON | IXANY;
	new.c_oflag = 0;
	new.c_cflag = old.c_cflag;
	new.c_lflag &= ~ECHO;

	if(wait_function != eash_ttynowait)
		fprintf(stderr, "[playback starting]\n");

	tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);
	process_function(input, speed, read_function, wait_function);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);

	if(wait_function != eash_ttynowait)
	{
		system("reset");
		fprintf(stderr, "[playback stopped]\n");
	}

	fclose(input);

	return(0);
}

void stop_playback(void)
{
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
	system("reset");
	fprintf(stderr, "[playback stopped]\n");
	exit(EXIT_SUCCESS);
}
