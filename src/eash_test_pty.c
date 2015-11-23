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

int main(int argc, char **argv)
{
	struct client_id c;

	setuid(getuid());

	if(get_client_id(&c) < 0)
		exit(EXIT_FAILURE);

	fprintf(stdout, "%-25s = uid=%i(%.63s) gid=%i(%.63s)\n", "Real ID", c.real_uid, c.real_pw_name, c.real_gid, c.real_gr_name);
	fprintf(stdout, "%-25s = uid=%i(%.63s) gid=%i(%.63s)\n", "Effective ID", c.effective_uid, c.effective_pw_name, c.effective_gid, c.effective_gr_name);
	fprintf(stdout, "%-25s = uid=%i(%.63s) gid=%i(%.63s) terminal=%.100s\n", "Originally logged on as", c.original_uid, c.original_pw_name, c.original_gid, c.original_gr_name, c.terminal);


	exit(EXIT_SUCCESS);
}
