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
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif

#include "io.h"

typedef double (*wait_func) (struct timeval, struct timeval, double);
typedef int (*read_func) (FILE *, Header *, char **);
typedef void (*write_func) (char *, int);
typedef void (*proccess_func) (FILE *, double, read_func, wait_func);

/* function declaration */
int playback(const char *);
void stop_playback(void);

/* globals */
char **saved_argv;
char progname[BUFSIZ];
read_func read_function;
wait_func wait_function;
proccess_func process_function;
struct termios old, new;
double maxwait;
double speed;

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
			{
				stop_playback();
			}

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
			case 'q':
			case 'x':
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
	eash_ttyplay(fp, speed, eash_ttypread, eash_ttywrite, wait_function);
}

int main(int argc, char **argv)
{
	extern int optind;
	int c = 0;

	memset(progname, '\0', sizeof(progname));
	strncpy(progname, argv[0], sizeof(progname) - 1);
	speed = 1;
	maxwait = 1;

	while((c = getopt(argc, argv, "d:hnw:svV")) != EOF)
	{
		switch(c)
		{
			case 'd':
				sscanf(optarg, "%lf", &speed);
				break;
			case 'w':
				sscanf(optarg, "%lf", &maxwait);
				break;
			case 'h':
			case '?':
				fprintf(stdout, "Usage: %.63s [-d speed] [-hns] [-w maxwait] [-v] FILE \n", basename(progname));
				fprintf(stdout, "Enterprise Audit Shell Play\n\n");
				fprintf(stdout, " -d\tspeed to playback - default is 1.0.\n");
				fprintf(stdout, " -h\tdisplay this help synopsis.\n");
				fprintf(stdout, " -n\tno wait - dump session to stdout.\n");
				fprintf(stdout, " -s\tsnoop on a running session.\n");
				fprintf(stdout, " -w\tmaximum time you want to want on the session.\n");
				fprintf(stdout, " -v\tdisplay version information.\n");
				exit(EXIT_SUCCESS);
				break;
			case 'n':
				wait_function = eash_ttynowait;
				break;
			case 'v':
			case 'V':
				fprintf(stdout, "%.63s (%.63s) version %.63s\n", basename(progname), PACKAGE_NAME, VERSION);
				exit(EXIT_SUCCESS);
				break;
			case 's':
				process_function = eash_ttypeek;
				break;
			default:
				fprintf(stderr, "Try `%.63s -h' for more information.\n", basename(progname));
				exit(EXIT_FAILURE);
				break;
		}
	}

	argc -= optind;
	argv += optind;

	switch(argc)
	{
		case 0:
			fprintf(stdout, "Usage: %.63s [-d speed] [-hns] [-w maxwait] [-v] FILE \n", basename(progname));
			fprintf(stdout, "Enterprise Audit Shell Play\n\n");
			fprintf(stdout, " -d\tspeed to playback.  Default is 1.0.\n");
			fprintf(stdout, " -h\tdisplay this help synopsis.\n");
			fprintf(stdout, " -n\tno wait - dump session to stdout.\n");
			fprintf(stdout, " -s\tsnoop on a running session.\n");
			fprintf(stdout, " -w\tmaximum time you want to want on the session.\n");
			fprintf(stdout, " -v\tdisplay version information.\n");
			exit(EXIT_SUCCESS);
			break;
		case 1:
			if(playback(*argv))
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

	fprintf(stderr, "%.63s: internal error.\n", basename(progname));
	exit(EXIT_FAILURE);
}

int playback(const char *file_session)
{
	FILE *input;

	read_function = eash_ttyread;
	wait_function = eash_ttywait;
	if(process_function != eash_ttypeek)
		process_function = eash_ttyplayback;

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

	fprintf(stderr, "[playback starting]\n");
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);
	process_function(input, speed, read_function, wait_function);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
	system("reset");
	fprintf(stderr, "[playback stopped]\n");

	fclose(input);

	return(0);
}

void stop_playback(void)
{
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        tcsetattr(STDIN_FILENO, TCSADRAIN, &old);
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
	system("reset");
        fprintf(stderr, "[playback stopped]\n");
        exit(EXIT_SUCCESS);
}
