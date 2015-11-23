struct ServerOption
{
	char *pemfile;
	char **cafiles;
	char *egdfile;
	char *randomfile;
	char *pidfile;
	char *listenaddress;
	char *cipher;
	char *sessiondirectory;
	char *hook;
	char sessiondb[BUFSIZ];
	int port;
	int sock;
	int lock_fd;
	int facility;
	int priority;
	int keepalive;
	int idletimeout;
	int hook_failure_critical;
	int hook_timeout;
	int sync;
	int strict_inode;
	int strict_mode;
	int strict_owner;
	int strict_ctime;
	int strict_mtime;
	enum { eERROR, eINFO, eDEBUG1, eDEBUG2, eDEBUG3 } level;
	enum { TLSv1, SSLv2, SSLv3, SSLv23 } eash_method;
	uid_t uid;
	gid_t gid;
	SSL_METHOD *method;
	SSL *ssl;
	SSL_CTX *ctx;
};

int load_config(const char *);
void init_options(void);
