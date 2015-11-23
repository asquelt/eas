#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/utsname.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rand.h"

#include "config.h"

#include "sql.h"
#include "../sqlite/sqlite3.h"

int main(int argc, char **argv)
{
	struct utsname u;

	fprintf(stdout, "Enterprise Audit Shell version information:\n");
	fprintf(stdout, " + %.63s version %.63s\n", PACKAGE_NAME, PACKAGE_VERSION);
        fprintf(stdout, "\nLibrary information:\n");
        fprintf(stdout, " + OpenSSL version 0x%lx\n", OPENSSL_VERSION_NUMBER);
        fprintf(stdout, " + SQLite version %.31s\n", SQLITE_VERSION);

        if(uname(&u) < 0)
        {
                fprintf(stderr, "uname: %.100s (%i)\n", strerror(errno), errno);
                exit(EXIT_FAILURE);
        }

        fprintf(stdout, "\nSystem information:\n");
        fprintf(stdout, " + Processor = %.255s\n", u.machine);
        fprintf(stdout, " + Machine = %.255s\n", u.nodename);
        fprintf(stdout, " + System = %.255s %.255s (%.255s)\n", u.sysname, u.release, u.version);

	exit(EXIT_SUCCESS);
}
