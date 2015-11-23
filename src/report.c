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

#include "../sqlite/sqlite3.h"

/* function declaration */
int detail_report(int);

/* globals */
struct ServerOption option;
struct client_info client;
char **saved_argv;
char progname[BUFSIZ];
char *css = (char *) 0;

int main(int argc, char **argv)
{
	extern int optind;
	int c = 0;
	int all = 0;
	int group = 0;
	int reverse = 0;
	int running = 0;
	int rows = 0;
	int col = 0;
	int limit = -1;
	char select[4096];
	char header[BUFSIZ];
	char css_buffer[BUFSIZ];
	char *ip = (char *) 0;
	char *from = (char *) 0;
	char *to = (char *) 0;
	time_t current_time;
	struct tm *t;
	FILE *css_file;

	sqlite3 *db;
	sqlite3_stmt *statement;

	memset(select, '\0', sizeof(select));
	strncpy(progname, argv[0], sizeof(progname) - 1);

	init_options();

	if(load_config(EASHD_CONFIG) < 0)
		exit(EXIT_FAILURE);

	if(sql_init_db(option.sessiondb) < 0)
		exit(EXIT_FAILURE);

	while((c = getopt(argc, argv, "ac:f:g?hi:l:t:rwvV")) != EOF)
	{
		switch(c)
		{
			case 'a':
				all = 1;
				break;
			case 'c':
				css = strdup(optarg);
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
				fprintf(stdout, "Usage: %.63s [-a] [-c css] [-f from] [-gh] [-i IP] [-l limit] [-t to] [-rwv]\n", basename(progname));
				fprintf(stdout, "Enterprise Audit Shell Report\n\n");
				fprintf(stdout, " -a\tshow all sessions.\n");
				fprintf(stdout, " -c\tpoint to another css file.\n");
				fprintf(stdout, " -f\tlimit records by the 'From' field.  E.g. `%.63s -f root'\n", basename(progname));
				fprintf(stdout, " -g\tgroup by username.\n");
				fprintf(stdout, " -h\tdisplay this help synopsis.\n");
				fprintf(stdout, " -i\tlimit records by the 'IP' field.  E.g. `%.63s -i 127.0.0.1'\n", basename(progname));
				fprintf(stdout, " -l\tlimit the number of records in general. E.g. `%.63s -l 10'\n", basename(progname));
				fprintf(stdout, " -t\tlimit records by the 'To' field.  E.g. `%.63s -t root'\n", basename(progname));
				fprintf(stdout, " -r\treverse sort.\n");
				fprintf(stdout, " -v\tdisplay version information.\n");
				exit(EXIT_SUCCESS);
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

	if(*argv)
	{
		exit(detail_report(atoi(*argv)));
	}

	if(sqlite3_open(option.sessiondb, &db))
	{
		fprintf(stderr, "sqlite3_open: %.100s", sqlite3_errmsg(db));
		exit(EXIT_FAILURE);
	}

	snprintf(select, sizeof(select) - 1,
		"SELECT created,real_pw_name,original_pw_name,ip,id,stype,status,file_session,hash_session FROM USER WHERE status != ? %.63s%.63s%.63s%.63s LIMIT ?;",
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

	sqlite3_bind_text(statement, col++, "R", -1, SQLITE_TRANSIENT);

	if(ip)
		sqlite3_bind_text(statement, col++, ip, -1, SQLITE_TRANSIENT);
	if(from)
		sqlite3_bind_text(statement, col++, from, -1, SQLITE_TRANSIENT);
	if(to)
		sqlite3_bind_text(statement, col++, to, -1, SQLITE_TRANSIENT);

	sqlite3_bind_int(statement, col++, limit);

	if((css_file = fopen(css ? css : "/etc/eas/css/report.css", "r")) == (FILE *) 0)
	{
		fprintf(stderr, "%.63s: %.127s: %.100s (%i)\n", basename(progname), css ? css : "/etc/eas/css/report.css", strerror(errno), errno);
		sqlite3_close(db);
		exit(EXIT_FAILURE);
	}

	current_time = time(0);
	t = localtime(&current_time);

	/* ISO8601 */
	strftime(header, sizeof(header) - 1, "%Y-%m-%d %H:%M:%S", t);
	
	fprintf(stdout, "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n");
	fprintf(stdout, "<html>\n");
	fprintf(stdout, "<head>\n");
	fprintf(stdout, "<title>%.127s</title>\n", header);
	fprintf(stdout, "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">\n");

	memset(css_buffer, '\0', sizeof(css_buffer));
	while(fgets(css_buffer, sizeof(css_buffer) - 1, css_file))
	{
		fprintf(stdout, css_buffer);
		memset(css_buffer, '\0', sizeof(css_buffer));
	}
	fclose(css_file);

	fprintf(stdout, "</head>\n");
	fprintf(stdout, "<body>\n");
	fprintf(stdout, "<h2>Enterprise Audit Shell Audit Report</h2>\n");
	fprintf(stdout, "<h3>%.127s</h3>\n", header);
	fprintf(stdout, "<table cellspacing=\"0\" summary=\"Enterprise Audit Shell Report - %s\">\n", header);
	fprintf(stdout, "<thead>\n");
	fprintf(stdout, "<tr>\n");
	fprintf(stdout, "\t<th class=\"hdate\">Date</th>\n");
	fprintf(stdout, "\t<th class=\"hfrom\">From</th>\n");
	fprintf(stdout, "\t<th class=\"hto\">To</th>\n");
	fprintf(stdout, "\t<th class=\"hip\">IP</th>\n");
	fprintf(stdout, "\t<th class=\"htype\">Type</th>\n");
	fprintf(stdout, "\t<th class=\"hsignature\">Signature</th>\n");
	fprintf(stdout, "\t<th class=\"hrowid\">ID</th>\n");
	fprintf(stdout, "</tr>\n");
	fprintf(stdout, "</thead>\n");
	fprintf(stdout, "<tbody>\n");

	running = 1;

	while(running)
	{
		int OK = 0;
		char type[BUFSIZ];

		memset(type, '\0', sizeof(type));

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
				*/

				memset(client.cid.created, '\0', sizeof(client.cid.created));
				memset(client.cid.real_pw_name, '\0', sizeof(client.cid.real_pw_name));
				memset(client.cid.original_pw_name, '\0', sizeof(client.cid.original_pw_name));
				memset(client.cid.ip, '\0', sizeof(client.cid.ip));
				memset(client.cid.type, '\0', sizeof(client.cid.type));
				memset(client.cid.status, '\0', sizeof(client.cid.status));
				memset(client.cid.file_session, '\0', sizeof(client.cid.file_session));
				memset(client.cid.hash_session, '\0', sizeof(client.cid.hash_session));

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
				if(sqlite3_column_text(statement, 7))
					strncpy(client.cid.file_session, (char *) sqlite3_column_text(statement, 7),
						sizeof(client.cid.file_session) - 1);
				if(sqlite3_column_text(statement, 8))
					strncpy(client.cid.hash_session, (char *) sqlite3_column_text(statement, 8),
						sizeof(client.cid.hash_session) - 1);

				if(create_SHA1(client.cid.file_session, option.strict_inode, option.strict_mode, option.strict_owner, option.strict_ctime, option.strict_mtime))
				{
					char a[BUFSIZ];

					strncpy(a, create_SHA1(client.cid.file_session, option.strict_inode, option.strict_mode, option.strict_owner, option.strict_ctime, option.strict_mtime), sizeof(a) - 1);

					if(!strcmp(a, client.cid.hash_session))
						OK = 1;
					else
						OK = 0;
				}
				else
				{
					OK = 0;
				}

				if(!strcmp(client.cid.type, "SESSION"))
					strcpy(type, "Session");
				else if(!strcmp(client.cid.type, "COMMAND"))
					strcpy(type, "Command");
				else if(!strcmp(client.cid.type, "LOGIN"))
					strcpy(type, "Login");
				else
					strcpy(type, "Unknown");

				fprintf(stdout, "<tr class=\"%.63s\">\n", rows % 2 ? "odd" : "even");
				fprintf(stdout, "\t<th class=\"date\">%.19s</th>\n", client.cid.created);
				fprintf(stdout, "\t<td class=\"from\">%.15s</td>\n", client.cid.original_pw_name);
				fprintf(stdout, "\t<td class=\"to\">%.15s</td>\n", client.cid.real_pw_name);
				fprintf(stdout, "\t<td class=\"ip\">%.15s</td>\n", client.cid.ip);
				fprintf(stdout, "\t<td class=\"type\">%.15s</td>\n", type);
				fprintf(stdout, "\t<td class=\"%.63s\">%.32s</td>\n", OK ? "verified" : "invalid", OK ? "Verified" : "Invalid");
				fprintf(stdout, "\t<td class=\"rowid\">%.9i</td>\n", client.cid.rowid);
				fprintf(stdout, "</tr>\n");
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
		fprintf(stdout, "<tr>\n\t<td class=\"norows\" colspan=7>No sessions found for the criteria.</td>\n</tr>");

	fprintf(stdout, "<tr>\n");
	fprintf(stdout, "\t<th class=\"empty\">&nbsp;</th>\n");
	fprintf(stdout, "\t<th class=\"total\" colspan=6>&nbsp;</th>\n");
	fprintf(stdout, "</tr>\n");
	fprintf(stdout, "<tbody>\n");
	fprintf(stdout, "</table>\n");
	fprintf(stdout, "</body>\n");
	fprintf(stdout, "</html>\n");

	exit(EXIT_SUCCESS);
}

int detail_report(int id)
{
	int running = 0;
	int rows = 0;
	int oerow = 1;
	int OK = 0;
	char select[4096];
	char tmp[BUFSIZ];
	char header[BUFSIZ];
	char css_buffer[BUFSIZ];
	FILE *css_file;
	time_t current_time;
	struct tm *t;
	sqlite3 *db;
	sqlite3_stmt *statement;

	if(sqlite3_open(option.sessiondb, &db))
	{
		fprintf(stderr, "sqlite3_open: %.100s", sqlite3_errmsg(db));
		return(-1);
	}

	strncpy(select, "SELECT id,real_uid,real_gid,effective_uid,effective_gid,original_uid,original_gid,port,duration,real_pw_name,real_gr_name,effective_pw_name,effective_gr_name,original_pw_name,original_gr_name,terminal,ip,status,stype,method,cipher,sysname,nodename,release,version,machine,file_session,hash_session,remote_command,pid,created,modified FROM USER WHERE id=?;", sizeof(select) - 1);

	sqlite3_busy_timeout(db, 2000);

	if(sqlite3_prepare(db, select, -1, &statement, NULL) != SQLITE_OK)
	{
		fprintf(stderr, "sqlite3_prepare: %.100s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return(-1);
	}

	sqlite3_bind_int(statement, 1, id);

	if((css_file = fopen(css ? css : "/etc/eas/css/detailed.css", "r")) == (FILE *) 0)
	{
		fprintf(stderr, "%.63s: %.127s: %.100s (%i)\n", basename(progname), css ? css : "/etc/eas/css/detailed.css", strerror(errno), errno);
		sqlite3_close(db);
		exit(EXIT_FAILURE);
	}

	current_time = time(0);
	t = localtime(&current_time);

	/* ISO8601 */
	strftime(header, sizeof(header) - 1, "%Y-%m-%d %H:%M:%S", t);
	
	fprintf(stdout, "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n");
	fprintf(stdout, "<html>\n");
	fprintf(stdout, "<head>\n");
	fprintf(stdout, "<title> %.63s %.127s</title>\n", client.cid.original_pw_name, header);
	fprintf(stdout, "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">\n");

	memset(css_buffer, '\0', sizeof(css_buffer));
	while(fgets(css_buffer, sizeof(css_buffer) - 1, css_file))
	{
		fprintf(stdout, css_buffer);
		memset(css_buffer, '\0', sizeof(css_buffer));
	}
	fclose(css_file);

	fprintf(stdout, "</head>\n");
	fprintf(stdout, "<body>\n");
	fprintf(stdout, "<h2>Enterprise Audit Shell Detailed Report</h2>\n");
	fprintf(stdout, "<h3>%.127s</h3>\n", header);
	fprintf(stdout, "<table cellspacing=\"0\" summary=\"Enterprise Audit Shell Report - %s\">\n", header);
	fprintf(stdout, "<tr>\n");

	running = 1;

	while(running)
	{
		switch(sqlite3_step(statement))
		{
			case SQLITE_DONE:
				running = 0;
				break;
			case SQLITE_ROW:
				/*
				 * 0 id
				 * 1 real_uid
				 * 2 real_gid
				 * 3 effective_uid
				 * 4 effective_gid
				 * 5 original_uid
				 * 6 original_gid
				 * 7 port
				 * 8 duration
				 * 9 real_pw_name
				 * 10 real_gr_name
				 * 11 effective_pw_name
				 * 12 effective_gr_name
				 * 13 original_pw_name
				 * 14 original_gr_name
				 * 15 terminal
				 * 16 ip
				 * 17 status
				 * 18 stype
				 * 19 method
				 * 20 cipher
				 * 21 sysname
				 * 22 nodename
				 * 23 release
				 * 24 version
				 * 25 machine
				 * 26 file_session
				 * 27 hash_session
				 * 28 remote_command
				 * 29 pid
				 * 30 created
				 * 31 modified
				*/

				rows++;

				client.cid.rowid = -1;
				client.cid.real_uid = -1;
				client.cid.real_gid = -1;
				client.cid.effective_uid = -1;
				client.cid.effective_gid = -1;
				client.cid.original_uid = -1;
				client.cid.original_gid = -1;
				client.cid.port = -1;
				client.cid.duration = -1;
				client.cid.pid = -1;

				memset(client.cid.real_pw_name, '\0', sizeof(client.cid.real_pw_name));
				memset(client.cid.real_gr_name, '\0', sizeof(client.cid.real_gr_name));
				memset(client.cid.effective_pw_name, '\0', sizeof(client.cid.effective_pw_name));
				memset(client.cid.effective_gr_name, '\0', sizeof(client.cid.effective_gr_name));
				memset(client.cid.original_pw_name, '\0', sizeof(client.cid.original_pw_name));
				memset(client.cid.original_gr_name, '\0', sizeof(client.cid.original_gr_name));
				memset(client.cid.terminal, '\0', sizeof(client.cid.terminal));
				memset(client.cid.ip, '\0', sizeof(client.cid.ip));
				memset(client.cid.status, '\0', sizeof(client.cid.status));
				memset(client.cid.stype, '\0', sizeof(client.cid.stype));
				memset(client.cid.method, '\0', sizeof(client.cid.method));
				memset(client.cid.cipher, '\0', sizeof(client.cid.cipher));
				memset(client.sysname, '\0', sizeof(client.sysname));
				memset(client.nodename, '\0', sizeof(client.nodename));
				memset(client.release, '\0', sizeof(client.release));
				memset(client.version, '\0', sizeof(client.version));
				memset(client.machine, '\0', sizeof(client.machine));
				memset(client.cid.file_session, '\0', sizeof(client.cid.file_session));
				memset(client.cid.hash_session, '\0', sizeof(client.cid.hash_session));
				memset(client.cid.remote_command, '\0', sizeof(client.cid.remote_command));
				memset(client.cid.created, '\0', sizeof(client.cid.created));
				memset(client.cid.modified, '\0', sizeof(client.cid.modified));

				client.cid.rowid = sqlite3_column_int(statement, 0);
				client.cid.real_uid = sqlite3_column_int(statement, 1);
				client.cid.real_gid = sqlite3_column_int(statement, 2);
				client.cid.effective_uid = sqlite3_column_int(statement, 3);
				client.cid.effective_gid = sqlite3_column_int(statement, 4);
				client.cid.original_uid = sqlite3_column_int(statement, 5);
				client.cid.original_gid = sqlite3_column_int(statement, 6);
				client.cid.port = sqlite3_column_int(statement, 7);
				client.cid.duration = sqlite3_column_int(statement, 8);

				if(sqlite3_column_text(statement, 9))
					strncpy(client.cid.real_pw_name, (char *) sqlite3_column_text(statement, 9),
						sizeof(client.cid.real_pw_name) - 1); 
				if(sqlite3_column_text(statement, 10))
					strncpy(client.cid.real_gr_name, (char *) sqlite3_column_text(statement, 10),
						sizeof(client.cid.real_gr_name) - 1); 
				if(sqlite3_column_text(statement, 11))
					strncpy(client.cid.effective_pw_name, (char *) sqlite3_column_text(statement, 11),
						sizeof(client.cid.effective_pw_name) - 1); 
				if(sqlite3_column_text(statement, 12))
					strncpy(client.cid.effective_gr_name, (char *) sqlite3_column_text(statement, 12),
						sizeof(client.cid.effective_gr_name) - 1); 
				if(sqlite3_column_text(statement, 13))
					strncpy(client.cid.original_pw_name, (char *) sqlite3_column_text(statement, 13),
						sizeof(client.cid.original_pw_name) - 1); 
				if(sqlite3_column_text(statement, 14))
					strncpy(client.cid.original_gr_name, (char *) sqlite3_column_text(statement, 14),
						sizeof(client.cid.original_gr_name) - 1); 
				if(sqlite3_column_text(statement, 15))
					strncpy(client.cid.terminal, (char *) sqlite3_column_text(statement, 15),
						sizeof(client.cid.terminal) - 1); 
				if(sqlite3_column_text(statement, 16))
					strncpy(client.cid.ip, (char *) sqlite3_column_text(statement, 16),
						sizeof(client.cid.ip) - 1); 
				if(sqlite3_column_text(statement, 17))
					strncpy(client.cid.status, (char *) sqlite3_column_text(statement, 17),
						sizeof(client.cid.status) - 1); 
				if(sqlite3_column_text(statement, 18))
					strncpy(client.cid.stype, (char *) sqlite3_column_text(statement, 18),
						sizeof(client.cid.stype) - 1); 
				if(sqlite3_column_text(statement, 19))
					strncpy(client.cid.method, (char *) sqlite3_column_text(statement, 19),
						sizeof(client.cid.method) - 1); 
				if(sqlite3_column_text(statement, 20))
					strncpy(client.cid.cipher, (char *) sqlite3_column_text(statement, 20),
						sizeof(client.cid.cipher) - 1); 
				if(sqlite3_column_text(statement, 21))
					strncpy(client.sysname, (char *) sqlite3_column_text(statement, 21),
						sizeof(client.sysname) - 1); 
				if(sqlite3_column_text(statement, 22))
					strncpy(client.nodename, (char *) sqlite3_column_text(statement, 22),
						sizeof(client.nodename) - 1); 
				if(sqlite3_column_text(statement, 23))
					strncpy(client.release, (char *) sqlite3_column_text(statement, 23),
						sizeof(client.release) - 1); 
				if(sqlite3_column_text(statement, 24))
					strncpy(client.version, (char *) sqlite3_column_text(statement, 24),
						sizeof(client.version) - 1); 
				if(sqlite3_column_text(statement, 25))
					strncpy(client.machine, (char *) sqlite3_column_text(statement, 25),
						sizeof(client.machine) - 1); 
				if(sqlite3_column_text(statement, 26))
					strncpy(client.cid.file_session, (char *) sqlite3_column_text(statement, 26),
						sizeof(client.cid.file_session) - 1); 
				if(sqlite3_column_text(statement, 27))
					strncpy(client.cid.hash_session, (char *) sqlite3_column_text(statement, 27),
						sizeof(client.cid.hash_session) - 1); 
				if(sqlite3_column_text(statement, 28))
					strncpy(client.cid.remote_command, (char *) sqlite3_column_text(statement, 28),
						sizeof(client.cid.remote_command) - 1); 

				client.cid.pid = sqlite3_column_int(statement, 29);

				if(sqlite3_column_text(statement, 30))
					strncpy(client.cid.created, (char *) sqlite3_column_text(statement, 30),
						sizeof(client.cid.created) - 1); 
				if(sqlite3_column_text(statement, 31))
					strncpy(client.cid.modified, (char *) sqlite3_column_text(statement, 31),
						sizeof(client.cid.modified) - 1); 
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
	{
		fprintf(stdout, "<tr>\n");
		fprintf(stdout, "\t<td>No session found for the criteria.</td>\n");
		fprintf(stdout, "</tr>\n");
		fprintf(stdout, "</table>\n");
		fprintf(stdout, "</body>\n");
		fprintf(stdout, "</html>\n");
		return(-1);
	}

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"rowid\">ID</th>\n");
	fprintf(stdout, "\t<td>%-.6i</td>\n", client.cid.rowid);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"type\">Type</th>\n");
	fprintf(stdout, "\t<td>%.63s</td>\n", client.cid.stype);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"status\">Status</th>\n");
	fprintf(stdout, "\t<td>%.63s</td>\n", client.cid.status);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"duration\">Duration</th>\n");
	fprintf(stdout, "\t<td>%i seconds.</td>\n", client.cid.duration);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"created\">Created</th>\n");
	fprintf(stdout, "\t<td>%.63s</td>\n", client.cid.created);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"modified\">Last modified</th>\n");
	fprintf(stdout, "\t<td>%.63s</td>\n", client.cid.modified);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"ip\">IP</th>\n");
	fprintf(stdout, "\t<td>%.15s:%i</td>\n", client.cid.ip, client.cid.port);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"method\">SSL Method</th>\n");
	fprintf(stdout, "\t<td>%.63s</td>\n", client.cid.method);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"cipher\">SSL Cipher</th>\n");
	fprintf(stdout, "\t<td>%.63s</td>\n", client.cid.cipher);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"system\">System</th>\n");
	fprintf(stdout, "\t<td>%.63s %.63s (%.63s)</td>\n", client.sysname, client.release, client.version);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"pid\">PID</th>\n");
	fprintf(stdout, "\t<td>%i</td>\n", client.cid.pid);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"terminal\">Terminal</th>\n");
	fprintf(stdout, "\t<td>%.63s</td>\n", client.cid.terminal);
	fprintf(stdout, "</tr>\n");

	if(!strcmp(client.cid.stype, "COMMAND"))
	{
		fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
		fprintf(stdout, "\t<th class=\"command\">Command</th>\n");
		fprintf(stdout, "\t<td>%.63s</td>\n", client.cid.remote_command);
		fprintf(stdout, "</tr>\n");
	}

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"original_pw_name\">Original user</th>\n");
	fprintf(stdout, "\t<td>uid=%i(%.63s) gid=%i(%.63s)</td>\n", client.cid.original_uid, client.cid.original_pw_name, client.cid.original_gid, client.cid.original_gr_name);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"real_pw_name\">Real user</th>\n");
	fprintf(stdout, "\t<td>uid=%i(%.63s) gid=%i(%.63s)</td>\n", client.cid.real_uid, client.cid.real_pw_name, client.cid.real_gid, client.cid.real_gr_name);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"effective_pw_name\">Effective user</th>\n");
	fprintf(stdout, "\t<td>uid=%i(%.63s) gid=%i(%.63s)</td>\n", client.cid.effective_uid, client.cid.effective_pw_name, client.cid.effective_gid, client.cid.effective_gr_name);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"session\">Session</th>\n");
	fprintf(stdout, "\t<td>%.127s</td>\n", client.cid.file_session);
	fprintf(stdout, "</tr>\n");

	memset(tmp, '\0', sizeof(tmp));
	if(create_SHA1(client.cid.file_session, option.strict_inode, option.strict_mode, option.strict_owner, option.strict_ctime, option.strict_mtime))
	{
		strncpy(tmp, create_SHA1(client.cid.file_session, option.strict_inode, option.strict_mode, option.strict_owner, option.strict_ctime, option.strict_mtime), sizeof(tmp) - 1);
		if(!strcmp(tmp, client.cid.hash_session))
		{
			memset(tmp, '\0', sizeof(tmp));
			snprintf(tmp, sizeof(tmp) - 1, "%.63s (signature verified)", client.cid.hash_session);
			OK = 1;
		}
		else
		{
			memset(tmp, '\0', sizeof(tmp));
			snprintf(tmp, sizeof(tmp) - 1, "%.63s (signature INVALID)", client.cid.hash_session);
			OK = 0;
		}
	}
	else
	{
		memset(tmp, '\0', sizeof(tmp));
		strncpy(tmp, "??? (signature INVALID)", sizeof(tmp) - 1);
		OK = 0;
	}

	fprintf(stdout, "<tr class=\"%.63s\">\n", oerow++ % 2 ? "odd" : "even");
	fprintf(stdout, "\t<th class=\"signature\">Signature</th>\n");
	fprintf(stdout, "\t<td class=\"%.63s\">%.127s</td>\n", OK ? "verified" : "invalid", tmp);
	fprintf(stdout, "</tr>\n");

	fprintf(stdout, "</table>\n");
	fprintf(stdout, "</body>\n");
	fprintf(stdout, "</html>\n");

	return(0);
}
