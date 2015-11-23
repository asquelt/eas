#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rand.h"

#include "config.h"

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "servconf.h"
#include "client_id.h"
#include "ssl.h"
#include "socket.h"
#include "sig.h"
#include "log.h"
#include "sql.h"

#include "../sqlite/sqlite3.h"

int sql_init_db(const char *file)
{
	sqlite3 *db;
	sqlite3_stmt *statement;
	int count = -1;
	char *TABLE_USER =
"CREATE TABLE USER\n"
"(\n"
" id     INTEGER PRIMARY KEY AUTOINCREMENT,\n"
" real_uid     INTEGER NOT NULL,\n"
" real_gid     INTEGER NOT NULL,\n"
" effective_uid   INTEGER NOT NULL,\n"
" effective_gid   INTEGER NOT NULL,\n"
" original_uid   INTEGER NOT NULL,\n"
" original_gid   INTEGER NOT NULL,\n"
" port   INTEGER NOT NULL,\n"
" duration     INTEGER NOT NULL,\n"
" real_pw_name   VARCHAR(63) NOT NULL,\n"
" real_gr_name   VARCHAR(63) NOT NULL,\n"
" effective_pw_name      VARCHAR(63) NOT NULL,\n"
" effective_gr_name      VARCHAR(63) NOT NULL,\n"
" original_pw_name       VARCHAR(63) NOT NULL,\n"
" original_gr_name       VARCHAR(63) NOT NULL,\n"
" terminal     VARCHAR(63) NOT NULL,\n"
" ip     VARCHAR(16) NOT NULL,\n"
" status     VARCHAR(63) NOT NULL,\n"
" stype   VARCHAR(63) NOT NULL,\n"
" method     VARCHAR(63) NOT NULL,\n"
" cipher     VARCHAR(63) NOT NULL,\n"
" sysname     VARCHAR(63) NOT NULL,\n"
" nodename     VARCHAR(63) NOT NULL,\n"
" release     VARCHAR(63) NOT NULL,\n"
" version     VARCHAR(63) NOT NULL,\n"
" machine     VARCHAR(63) NOT NULL,\n"
" file_session   VARCHAR(63),\n"
" hash_session   VARCHAR(63),\n"
" dns    VARCHAR(127),\n"
" remote_command     VARCHAR(255),\n"
" pid     INTEGER NOT NULL,\n"
" created      DATETIME,\n"
" modified     DATETIME\n"
");\n"
"\n"
"CREATE TRIGGER INSERT_USER_CREATED AFTER INSERT ON USER\n"
"BEGIN\n"
" UPDATE USER SET created = DATETIME('now', 'localtime') WHERE id = new.id;\n"
" UPDATE USER SET modified = DATETIME('now', 'localtime') WHERE id = new.id;\n"
"END;\n"
"\n"
"CREATE TRIGGER INSERT_USER_MODIFIED AFTER UPDATE ON USER\n"
"BEGIN\n"
" UPDATE USER SET modified = DATETIME('now', 'localtime') WHERE id = new.id;\n"
"END;";

	if(sqlite3_open(file, &db))
	{
		s_log(eERROR, "sqlite3_open(%.100s): %.100s", file, sqlite3_errmsg(db));
		sqlite3_close(db);
		return(-1);
	}

	if(sqlite3_prepare(db, "SELECT COUNT(*) FROM sqlite_master WHERE name=? AND type=?;", -1, &statement, NULL) != SQLITE_OK)
	{
		s_log(eERROR, "sqlite3_prepare: %.100s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return(-1);
	}

	sqlite3_bind_text(statement, 1, "USER", -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(statement, 2, "table", -1, SQLITE_TRANSIENT);

	sqlite3_busy_timeout(db, 2000);

	switch(sqlite3_step(statement))
	{
		case SQLITE_ROW:
			count = sqlite3_column_int(statement, 0);
			break;
		case SQLITE_DONE:
			break;
		default:
			s_log(eERROR, "sqlite3_step: %.100s", sqlite3_errmsg(db));
			break;
	}

	sqlite3_finalize(statement);

	if(count <= 0)
	{
		s_log(eINFO, "sqlite3: creating table 'USER'");
		switch(sqlite3_exec(db, TABLE_USER, NULL, NULL, NULL))
		{
			case SQLITE_OK:
				break;
			default:
				s_log(eERROR, "sqlite3_exec: %.100s", sqlite3_errmsg(db));
				break;
		}
	}
	else
	{
		s_log(eDEBUG1, "table USER found");
		sqlite3_close(db);

		if(chmod(file, 0600) < 0)
		{
			s_log(eERROR, "chmod(%.100s, 0600): %.100s (%i)", file, strerror(errno), errno);
			return(-1);
		}

		return(1);
	}

	sqlite3_close(db);

	if(chmod(file, 0600) < 0)
	{
		s_log(eERROR, "chmod(%.100s, 0600): %.100s (%i)", file, strerror(errno), errno);
		return(-1);
	}

	return(0);
}

