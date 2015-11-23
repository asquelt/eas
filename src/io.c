#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "io.h"

#define SWAP_ENDIAN(val) ((unsigned int) ( \
	(((unsigned int) (val) & (unsigned int) 0x000000ffU) << 24) | \
	(((unsigned int) (val) & (unsigned int) 0x0000ff00U) <<  8) | \
	(((unsigned int) (val) & (unsigned int) 0x00ff0000U) >>  8) | \
	(((unsigned int) (val) & (unsigned int) 0xff000000U) >> 24)))

static int is_little_endian(void)
{
	static int retval = -1;

	if(retval == -1)
	{
		int n = 1;
		char *p = (char *) &n;
		char x[] = {1, 0, 0, 0};

		assert(sizeof(int) == 4);

		if(memcmp(p, x, 4) == 0)
			retval = 1;
		else
			retval = 0;
	}

	return retval;
}

static int convert_to_little_endian(int x)
{
	if(is_little_endian())
		return x;
	else
		return SWAP_ENDIAN(x);
}

int read_header(FILE *fp, Header *h)
{
	int buf[3];

	if(fread(buf, sizeof(int), 3, fp) == 0)
		return 0;

	h->tv.tv_sec  = convert_to_little_endian(buf[0]);
	h->tv.tv_usec = convert_to_little_endian(buf[1]);
	h->len = convert_to_little_endian(buf[2]);

	return 1;
}

int write_header(FILE *fp, Header *h)
{
	int buf[3];

	buf[0] = convert_to_little_endian(h->tv.tv_sec);
	buf[1] = convert_to_little_endian(h->tv.tv_usec);
	buf[2] = convert_to_little_endian(h->len);

	if (fwrite(buf, sizeof(int), 3, fp) == 0)
		return 0;

	return 1;
}
