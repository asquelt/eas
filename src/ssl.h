#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rand.h"

struct client_info
{
	char sysname[BUFSIZ];
	char nodename[BUFSIZ];
	char release[BUFSIZ];
	char version[BUFSIZ];
	char machine[BUFSIZ];
	char where[BUFSIZ];
	struct client_id cid;
};

int ssl_init_accept(SSL_CTX **, SSL_METHOD *, char *, char **, char *);
int ssl_wait_for_connection(int, int, SSL **, SSL_CTX *);
int ssl_check_retcode (SSL *, int);
int ssl_multiplex_loop(SSL *, struct client_info *, int, int, int);
int ssl_connect_ip(struct in_addr *, unsigned short, unsigned short, SSL **, SSL_CTX **, SSL_METHOD *, int, int);
int ssl_close_connection(SSL *, SSL_CTX *);
int ssl_handshake_timeout(SSL *, int, int);
int ssl_close_all(int, SSL *, SSL_CTX *);
void ssl_seed(const char *, const char *);
size_t my_read(SSL *, char *);
size_t ssl_readline(SSL *, char *, size_t);
int parse_protocol(SSL *, struct client_info *, const void *);
int lutil_b64_ntop(unsigned char const *, size_t, char *, size_t);
int lutil_b64_pton(char const *, unsigned char *, size_t);
int ssl_timeout(int, unsigned, unsigned);
size_t ssl_write(SSL *, void *, size_t);
size_t ssl_read(SSL *, void *, size_t);
void SSL_close_all(SSL *, SSL_CTX *, int);
char *create_SHA1(const char *, int, int, int, int, int);
