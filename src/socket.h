#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/rand.h"

struct s_cnx
{
	struct in_addr dip;
	unsigned short sport;
	unsigned short dport;
	int sock;
	SSL *ssl;
	SSL_CTX *ctx;
	SSL_METHOD *method;
};

int set_reuseaddr(int, int);
int listen_sock(unsigned short int);
int bind_sock(unsigned short int);
int wait_for_connect(int, struct client_info *);
int wait_for_connect_daemon(int, struct client_info *);
int connect_tcp(struct in_addr *, unsigned short, unsigned short, int, int);
int set_nonblocking_mode(int);
int unset_nonblocking_mode(int, int);
int data_available (int, int);
in_addr_t resolve_host_name(char *);

#define BSIZ 16384
