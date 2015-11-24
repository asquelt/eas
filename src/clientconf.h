struct ClientOption
{
	char *pemfile;
	char **cafiles;
	char **log_servers;
	char *egdfile;
	char *randomfile;
	char *cipher;
	char *default_shell;
	char *banner;
	char *shutup;
	char *copyenv;
	char *flowcontrol;
	int port;
	int banner_pause;
	int facility;
	int priority;
	int tcptimeout;
	enum { eERROR, eINFO, eDEBUG1, eDEBUG2, eDEBUG3 } level;
	enum { TLSv1, SSLv2, SSLv3, SSLv23 } eash_method;
	uid_t uid;
	gid_t gid;
	SSL_METHOD *method;
};

int load_config(const char *);
void init_options(void);
