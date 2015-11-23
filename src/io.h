#ifndef __IO_H
#define __IO_H

typedef struct header
{
	struct timeval tv;
	int len;
} Header;

int read_header(FILE *, Header *);
int write_header(FILE *, Header *);

#endif
