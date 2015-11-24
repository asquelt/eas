#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include "client_id.h"

int get_client_id(struct client_id *c)
{
	struct stat s;
	struct passwd *pw;
	struct group *gr;

	if((pw = getpwuid(getuid())) == (struct passwd *) 0)
	{
		fprintf(stderr, "getpwuid(%i): %.100s (%i)\n", getuid(), strerror(errno), errno);
		return(-1);
	}

	if((gr = getgrgid(getgid())) == (struct group *) 0)
	{
		fprintf(stderr, "getgrgid(%i): %.100s (%i)\n", getgid(), strerror(errno), errno);
		return(-1);
	}

	memset(c->real_pw_name, '\0', sizeof(c->real_pw_name));
	memset(c->real_gr_name, '\0', sizeof(c->real_gr_name));
	memset(c->shell, '\0', sizeof(c->shell));

	strncpy(c->real_pw_name, pw->pw_name, sizeof(c->real_pw_name) - 1);
	strncpy(c->real_gr_name, gr->gr_name, sizeof(c->real_gr_name) - 1);
	strncpy(c->shell, pw->pw_shell, sizeof(c->shell) - 1);
	strncpy(c->home, pw->pw_dir, sizeof(c->home) - 1);

	c->real_uid = getuid();
	c->real_gid = getgid();

	if((pw = getpwuid(geteuid())) == (struct passwd *) 0)
	{
		fprintf(stderr, "getpwuid(%i): %.100s (%i)\n", geteuid(), strerror(errno), errno);
		return(-1);
	}

	if((gr = getgrgid(getegid())) == (struct group *) 0)
	{
		fprintf(stderr, "getgrgid(%i): %.100s (%i)\n", getegid(), strerror(errno), errno);
		return(-1);
	}

	memset(c->effective_pw_name, '\0', sizeof(c->effective_pw_name));
	memset(c->effective_gr_name, '\0', sizeof(c->effective_gr_name));

	strncpy(c->effective_pw_name, pw->pw_name, sizeof(c->effective_pw_name) - 1);
	strncpy(c->effective_gr_name, gr->gr_name, sizeof(c->effective_gr_name) - 1);

	c->effective_uid = geteuid();
	c->effective_gid = getegid();

	if(ttyname(STDIN_FILENO))
	{
		memset(c->terminal, '\0', sizeof(c->terminal));
		strncpy(c->terminal, ttyname(STDIN_FILENO), sizeof(c->terminal) - 1);

		if(stat(c->terminal, &s) < 0)
		{
			fprintf(stderr, "stat: %.100s: %.100s (%i)\n", c->terminal, strerror(errno), errno);
			return(-1);
		}

		if((pw = getpwuid(s.st_uid)) == (struct passwd *) 0)
		{
			fprintf(stderr, "getpwuid(%i): %.100s (%i)\n", s.st_uid, strerror(errno), errno);
			return(-1);
		}

		memset(c->original_pw_name, '\0', sizeof(c->original_pw_name));
		strncpy(c->original_pw_name, pw->pw_name, sizeof(c->original_pw_name) - 1);
		c->original_uid = s.st_uid;

		if((pw = getpwuid(s.st_uid)) == (struct passwd *) 0)
		{
			fprintf(stderr, "getpwuid(%i): %.100s (%i)\n", s.st_uid, strerror(errno), errno);
			return(-1);
		}

		c->original_gid = pw->pw_gid;

		if((gr = getgrgid(c->original_gid)) == (struct group *) 0)
		{
			fprintf(stderr, "getgrgid(%i): %.100s (%i)\n", c->original_gid, strerror(errno), errno);
			return(-1);
		}

		memset(c->original_gr_name, '\0', sizeof(c->original_gr_name));
		strncpy(c->original_gr_name, gr->gr_name, sizeof(c->original_pw_name) - 1);
	}
	else
	{
		/* ttyname() from above failed - so set the terminal string to the error message */
		if(!isatty(STDIN_FILENO))
			snprintf(c->terminal, sizeof(c->terminal) - 1, "not a terminal");
		else if(strerror(errno))
			snprintf(c->terminal, sizeof(c->terminal) - 1, "error: %.100s (%i)", strerror(errno), errno);
		else
			snprintf(c->terminal, sizeof(c->terminal) - 1, "error: ttyname() failed and no errno was set");

		if((pw = getpwuid(geteuid())) == (struct passwd *) 0)
		{
			fprintf(stderr, "getpwuid(%i: %.100s (%i)\n", geteuid(), strerror(errno), errno);
			return(-1);
		}

		memset(c->original_pw_name, '\0', sizeof(c->original_pw_name));
		strncpy(c->original_pw_name, pw->pw_name, sizeof(c->original_pw_name) - 1);

		c->original_uid = pw->pw_uid;
		c->original_gid = pw->pw_gid;

		if((gr = getgrgid(c->original_gid)) == (struct group *) 0)
		{
			fprintf(stderr, "getgrgid(%i): %.100s (%i)\n", c->original_gid, strerror(errno), errno);
			return(-1);
		}

		memset(c->original_gr_name, '\0', sizeof(c->original_gr_name));
		strncpy(c->original_gr_name, gr->gr_name, sizeof(c->original_pw_name) - 1);
	}

	snprintf(c->user_string, sizeof(c->user_string) - 1, "USER\a%.63s\a%i\a%.63s\a%i\a%.63s\a%i\a%.63s\a%i\a%.63s\a%i\a%.63s\a%i\a%.100s\n",
		c->original_pw_name, c->original_uid,
		c->original_gr_name, c->original_gid,
		c->real_pw_name, c->real_uid, c->real_gr_name, c->real_gid,
		c->effective_pw_name, c->effective_uid, c->effective_gr_name, c->effective_gid,
		c->terminal);

	return(0);
}
