/*
 * ddosshield - OpenBSD DDoS detection and remote syslog reporter
 *
 * Periodically polls the pf(4) state table via pfctl(8), counts
 * connections per source IP, and forwards a RFC 3164 syslog message
 * over UDP to a remote syslog server whenever a source IP exceeds the
 * configured connection threshold within the sampling interval.
 *
 * Build:   make
 * Usage:   ddosshield [-v] [-c config] [-H host] [-p port]
 *                     [-t threshold] [-i interval]
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PROGNAME		"ddosshield"
#define DEFAULT_CONF		"/etc/ddosshield.conf"
#define PFCTL_CMD		"pfctl -s state 2>/dev/null"

/* Remote syslog defaults */
#define DEFAULT_PORT		514
#define DEFAULT_THRESHOLD	100	/* connections per interval */
#define DEFAULT_INTERVAL	10	/* seconds */

/* RFC 3164: facility LOCAL0 (16), severity WARNING (4) */
#define SYSLOG_PRI		((16 * 8) + 4)

/* Hash table sizing */
#define HASH_SIZE		4096

#define MAX_ADDR_LEN		46	/* max IPv6 string length + NUL */
#define MAX_LINE_LEN		512
#define MAX_HOST_LEN		256

/* Per-source-IP tracking entry */
struct ip_entry {
	char		 addr[MAX_ADDR_LEN];
	int		 count;
	int		 alerted;
	struct ip_entry	*next;
};

/* Runtime configuration */
static struct {
	char	remote_host[MAX_HOST_LEN];
	int	remote_port;
	int	threshold;
	int	interval;
	int	verbose;
} cfg = {
	.remote_host	= "",
	.remote_port	= DEFAULT_PORT,
	.threshold	= DEFAULT_THRESHOLD,
	.interval	= DEFAULT_INTERVAL,
	.verbose	= 0,
};

static int			 sockfd = -1;
static struct sockaddr_in	 remote_sa;
static volatile sig_atomic_t	 running = 1;

/* Hash table of source IP entries, reset each interval */
static struct ip_entry		*iptable[HASH_SIZE];

static void
handle_signal(int sig)
{
	(void)sig;
	running = 0;
}

/*
 * Send an RFC 3164 syslog message to the remote server over UDP.
 * Format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
 */
static int
remote_syslog(const char *fmt, ...)
{
	char		 msg[512];
	char		 buf[1024];
	char		 ts[32];
	char		 hostname[256];
	va_list		 ap;
	time_t		 now;
	struct tm	*tm;
	int		 n;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	now = time(NULL);
	tm = localtime(&now);
	strftime(ts, sizeof(ts), "%b %e %H:%M:%S", tm);

	if (gethostname(hostname, sizeof(hostname)) == -1)
		strlcpy(hostname, "localhost", sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';

	n = snprintf(buf, sizeof(buf), "<%d>%s %s %s: %s",
	    SYSLOG_PRI, ts, hostname, PROGNAME, msg);
	if (n < 0)
		return -1;
	if (n >= (int)sizeof(buf))
		n = sizeof(buf) - 1;

	if (sendto(sockfd, buf, (size_t)n, 0,
	    (struct sockaddr *)&remote_sa, sizeof(remote_sa)) == -1) {
		if (cfg.verbose)
			warn("sendto remote syslog");
		return -1;
	}
	return 0;
}

/* djb2-based hash for an IP address string */
static unsigned int
hash_addr(const char *addr)
{
	unsigned int	 h = 5381;
	int		 c;

	while ((c = (unsigned char)*addr++) != '\0')
		h = ((h << 5) + h) ^ (unsigned int)c;
	return h % HASH_SIZE;
}

/* Look up or allocate an ip_entry for addr */
static struct ip_entry *
ip_entry_get(const char *addr)
{
	unsigned int	 h = hash_addr(addr);
	struct ip_entry	*e;

	for (e = iptable[h]; e != NULL; e = e->next) {
		if (strcmp(e->addr, addr) == 0)
			return e;
	}

	e = calloc(1, sizeof(*e));
	if (e == NULL)
		return NULL;
	strlcpy(e->addr, addr, sizeof(e->addr));
	e->next = iptable[h];
	iptable[h] = e;
	return e;
}

/* Free all entries in the hash table */
static void
iptable_reset(void)
{
	struct ip_entry	*e, *next;
	int		 i;

	for (i = 0; i < HASH_SIZE; i++) {
		for (e = iptable[i]; e != NULL; e = next) {
			next = e->next;
			free(e);
		}
		iptable[i] = NULL;
	}
}

/*
 * Extract the source IP address from a pfctl -s state output line.
 *
 * Line format (columns separated by whitespace):
 *   <iface> <proto> <src_addr:port> -> <dst_addr:port> -> <state>
 *
 * IPv4 src: "192.0.2.1:12345"   → extract everything before last ':'
 * IPv6 src: "[2001:db8::1]:12345" → strip brackets and port
 *
 * Returns 0 on success with addr filled in, -1 if line cannot be parsed.
 */
static int
parse_src_addr(const char *line, char *addr, size_t addrlen)
{
	const char	*p = line;
	const char	*field, *end, *colon;
	size_t		 flen;
	int		 i;

	/* Skip the first two whitespace-separated fields (iface, proto) */
	for (i = 0; i < 2; i++) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '\0')
			return -1;
		while (*p != ' ' && *p != '\t' && *p != '\0')
			p++;
	}

	/* Skip leading whitespace before the source field */
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == '\0')
		return -1;

	field = p;
	/* The source field ends at the next whitespace */
	end = field;
	while (*end != ' ' && *end != '\t' && *end != '\0')
		end++;
	flen = (size_t)(end - field);

	if (flen == 0 || flen >= MAX_LINE_LEN)
		return -1;

	if (field[0] == '[') {
		/* IPv6: [addr]:port – strip brackets and port */
		const char *bracket_close = memchr(field, ']', flen);
		if (bracket_close == NULL)
			return -1;
		size_t ilen = (size_t)(bracket_close - field) - 1;
		if (ilen == 0 || ilen >= addrlen)
			return -1;
		memcpy(addr, field + 1, ilen);
		addr[ilen] = '\0';
	} else {
		/* IPv4: addr:port – everything before the last colon */
		char tmp[MAX_LINE_LEN];
		if (flen >= sizeof(tmp))
			return -1;
		memcpy(tmp, field, flen);
		tmp[flen] = '\0';
		colon = strrchr(tmp, ':');
		if (colon == NULL)
			return -1;
		size_t ilen = (size_t)(colon - tmp);
		if (ilen == 0 || ilen >= addrlen)
			return -1;
		memcpy(addr, tmp, ilen);
		addr[ilen] = '\0';
	}

	return 0;
}

/* Poll pfctl state table and check for threshold violations */
static void
check_states(void)
{
	FILE		*fp;
	char		 line[MAX_LINE_LEN];
	char		 src[MAX_ADDR_LEN];
	struct ip_entry	*e;

	fp = popen(PFCTL_CMD, "r");
	if (fp == NULL) {
		warn("popen: " PFCTL_CMD);
		return;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (parse_src_addr(line, src, sizeof(src)) == -1)
			continue;

		/* Skip loopback addresses */
		if (strncmp(src, "127.", 4) == 0 || strcmp(src, "::1") == 0)
			continue;

		e = ip_entry_get(src);
		if (e == NULL)
			continue;
		e->count++;

		if (!e->alerted && e->count >= cfg.threshold) {
			const char *msg_fmt =
			    "Suspected DDoS attack from %s: "
			    "%d connections within %d seconds";

			if (cfg.verbose)
				fprintf(stderr, PROGNAME ": " msg_fmt "\n",
				    src, e->count, cfg.interval);

			remote_syslog(msg_fmt, src, e->count, cfg.interval);
			e->alerted = 1;
		}
	}
	pclose(fp);
}

/* Parse a simple "key value" configuration file */
static void
parse_config(const char *path)
{
	FILE	*fp;
	char	 line[256];
	char	 key[64], val[192];

	fp = fopen(path, "r");
	if (fp == NULL) {
		if (errno != ENOENT)
			warn("fopen: %s", path);
		return;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		/* Skip blank lines and comments */
		if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
			continue;
		if (sscanf(line, "%63s %191s", key, val) != 2)
			continue;
		if (strcmp(key, "remote_host") == 0)
			strlcpy(cfg.remote_host, val, sizeof(cfg.remote_host));
		else if (strcmp(key, "remote_port") == 0)
			cfg.remote_port = atoi(val);
		else if (strcmp(key, "threshold") == 0)
			cfg.threshold = atoi(val);
		else if (strcmp(key, "interval") == 0)
			cfg.interval = atoi(val);
	}
	fclose(fp);
}

static void __dead
usage(void)
{
	fprintf(stderr,
	    "usage: " PROGNAME " [-v] [-c config] [-H host] [-p port]"
	    " [-t threshold] [-i interval]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char	*conffile = DEFAULT_CONF;
	struct hostent	*he;
	int		 ch;

	/* Load config file first; CLI flags override below */
	parse_config(conffile);

	while ((ch = getopt(argc, argv, "vc:H:p:t:i:")) != -1) {
		switch (ch) {
		case 'v':
			cfg.verbose = 1;
			break;
		case 'c':
			conffile = optarg;
			parse_config(conffile);
			break;
		case 'H':
			strlcpy(cfg.remote_host, optarg,
			    sizeof(cfg.remote_host));
			break;
		case 'p':
			cfg.remote_port = atoi(optarg);
			break;
		case 't':
			cfg.threshold = atoi(optarg);
			break;
		case 'i':
			cfg.interval = atoi(optarg);
			break;
		default:
			usage();
		}
	}

	if (cfg.remote_host[0] == '\0')
		errx(1, "remote_host not configured (use -H or set in %s)",
		    conffile);
	if (cfg.threshold <= 0)
		errx(1, "threshold must be a positive integer");
	if (cfg.interval <= 0)
		errx(1, "interval must be a positive integer");

	/* Resolve remote syslog host before pledging */
	he = gethostbyname(cfg.remote_host);
	if (he == NULL)
		errx(1, "cannot resolve host: %s", cfg.remote_host);

	memset(&remote_sa, 0, sizeof(remote_sa));
	remote_sa.sin_family = AF_INET;
	remote_sa.sin_port = htons((uint16_t)cfg.remote_port);
	memcpy(&remote_sa.sin_addr, he->h_addr_list[0],
	    (size_t)he->h_length);

	/* Open UDP socket for remote syslog */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1)
		err(1, "socket");

	signal(SIGTERM, handle_signal);
	signal(SIGINT,  handle_signal);

	/*
	 * Restrict privileges with pledge(2).
	 * "proc exec" covers popen/pclose; "inet" covers UDP sendto;
	 * "stdio" covers file I/O and time.
	 */
#ifdef __OpenBSD__
	if (pledge("stdio proc exec inet", NULL) == -1)
		err(1, "pledge");
#endif

	if (cfg.verbose)
		fprintf(stderr,
		    PROGNAME ": started — remote=%s:%d threshold=%d "
		    "interval=%ds\n",
		    cfg.remote_host, cfg.remote_port,
		    cfg.threshold, cfg.interval);

	while (running) {
		check_states();
		sleep((unsigned int)cfg.interval);
		iptable_reset();
	}

	close(sockfd);
	iptable_reset();
	return 0;
}
