#import <Foundation/Foundation.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* RFC 3164 syslog: LOCAL0 facility (16), WARNING severity (4) */
#define SYSLOG_PRI ((16 * 8) + 4)

static volatile int running = 1;

static void
handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* ------------------------------------------------------------------ */
/* DDOSShield                                                           */
/* ------------------------------------------------------------------ */

@interface DDOSShield : NSObject {
    NSString            *_remoteHost;
    int                  _remotePort;
    int                  _threshold;
    int                  _interval;
    BOOL                 _verbose;
    int                  _sockfd;
    struct sockaddr_in   _remoteSA;
    NSMutableDictionary *_ipCounts;   /* NSString -> NSNumber (count)  */
    NSMutableDictionary *_ipAlerted;  /* NSString -> NSNumber (BOOL)   */
}

- (id)init;
- (void)dealloc;

/* Accessors */
- (NSString *)remoteHost;
- (void)setRemoteHost:(NSString *)host;
- (int)remotePort;
- (void)setRemotePort:(int)port;
- (int)threshold;
- (void)setThreshold:(int)t;
- (int)interval;
- (void)setInterval:(int)i;
- (BOOL)verbose;
- (void)setVerbose:(BOOL)v;

/* Operations */
- (void)loadConfig:(NSString *)path;
- (BOOL)setupSocket;
- (void)run;

@end

@implementation DDOSShield

- (id)init
{
    self = [super init];
    if (self) {
        _remoteHost = nil;
        _remotePort = 514;
        _threshold  = 100;
        _interval   = 10;
        _verbose    = NO;
        _sockfd     = -1;
        _ipCounts   = [[NSMutableDictionary alloc] init];
        _ipAlerted  = [[NSMutableDictionary alloc] init];
    }
    return self;
}

- (void)dealloc
{
    [_remoteHost release];
    [_ipCounts   release];
    [_ipAlerted  release];
    if (_sockfd != -1)
        close(_sockfd);
    [super dealloc];
}

/* --- Accessors ---------------------------------------------------- */

- (NSString *)remoteHost              { return _remoteHost; }
- (void)setRemoteHost:(NSString *)host
{
    [host retain];
    [_remoteHost release];
    _remoteHost = host;
}
- (int)remotePort                     { return _remotePort; }
- (void)setRemotePort:(int)port       { _remotePort = port; }
- (int)threshold                      { return _threshold; }
- (void)setThreshold:(int)t           { _threshold = t; }
- (int)interval                       { return _interval; }
- (void)setInterval:(int)i            { _interval = i; }
- (BOOL)verbose                       { return _verbose; }
- (void)setVerbose:(BOOL)v            { _verbose = v; }

/* --- Configuration ------------------------------------------------ */

/*
 * Parse a simple "key value" configuration file.
 * Lines beginning with '#' and blank lines are ignored.
 */
- (void)loadConfig:(NSString *)path
{
    NSString *content = [NSString stringWithContentsOfFile:path
                                                  encoding:NSUTF8StringEncoding
                                                     error:nil];
    if (!content)
        return;

    NSArray      *lines = [content componentsSeparatedByString:@"\n"];
    NSEnumerator *en    = [lines objectEnumerator];
    NSString     *line;

    while ((line = [en nextObject]) != nil) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:
            [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if ([trimmed length] == 0 || [trimmed hasPrefix:@"#"])
            continue;

        /* Split on any whitespace, skip empty tokens */
        NSArray        *parts  = [trimmed componentsSeparatedByCharactersInSet:
            [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        NSMutableArray *tokens = [NSMutableArray array];
        NSEnumerator   *pen    = [parts objectEnumerator];
        NSString       *p;
        while ((p = [pen nextObject]) != nil) {
            if ([p length] > 0)
                [tokens addObject:p];
        }
        if ([tokens count] < 2)
            continue;

        NSString *key = [tokens objectAtIndex:0];
        NSString *val = [tokens objectAtIndex:1];

        if ([key isEqualToString:@"remote_host"])
            [self setRemoteHost:val];
        else if ([key isEqualToString:@"remote_port"])
            _remotePort = [val intValue];
        else if ([key isEqualToString:@"threshold"])
            _threshold = [val intValue];
        else if ([key isEqualToString:@"interval"])
            _interval = [val intValue];
    }
}

/* --- Networking --------------------------------------------------- */

/* Resolve the remote host and open the UDP socket. */
- (BOOL)setupSocket
{
    struct addrinfo  hints, *res;
    int              err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    err = getaddrinfo([_remoteHost UTF8String], NULL, &hints, &res);
    if (err != 0) {
        NSLog(@"ddosshield: cannot resolve host %@: %s",
            _remoteHost, gai_strerror(err));
        return NO;
    }

    memset(&_remoteSA, 0, sizeof(_remoteSA));
    _remoteSA.sin_family = AF_INET;
    _remoteSA.sin_port   = htons((uint16_t)_remotePort);
    _remoteSA.sin_addr   = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);

    _sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (_sockfd == -1) {
        NSLog(@"ddosshield: socket: %s", strerror(errno));
        return NO;
    }
    return YES;
}

/*
 * Send an RFC 3164 syslog message to the remote server over UDP.
 * Format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
 */
- (void)sendSyslog:(NSString *)message
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    time_t    now = time(NULL);
    struct tm *tm = localtime(&now);
    char       tsbuf[32];
    strftime(tsbuf, sizeof(tsbuf), "%b %e %H:%M:%S", tm);

    NSString *hostname = [[NSProcessInfo processInfo] hostName];
    NSString *packet   = [NSString stringWithFormat:@"<%d>%s %@ ddosshield: %@",
        SYSLOG_PRI, tsbuf, hostname, message];

    const char *buf = [packet UTF8String];
    size_t      len = strlen(buf);

    if (sendto(_sockfd, buf, len, 0,
               (struct sockaddr *)&_remoteSA, sizeof(_remoteSA)) == -1) {
        if (_verbose)
            NSLog(@"ddosshield: sendto: %s", strerror(errno));
    }

    [pool drain];
}

/* --- pf state parsing --------------------------------------------- */

/*
 * Extract the source IP address from a pfctl(8) -s state line.
 *
 * Line format (whitespace-separated):
 *   <iface> <proto> <src_addr:port> -> <dst_addr:port> -> <state>
 *
 * IPv4 src:  "192.0.2.1:12345"     → strip last ':' and port
 * IPv6 src:  "[2001:db8::1]:12345" → strip brackets and port
 *
 * Returns nil when the line cannot be parsed.
 */
- (NSString *)parseSrcFromLine:(NSString *)line
{
    NSArray        *fields = [line componentsSeparatedByCharactersInSet:
        [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSMutableArray *tokens = [NSMutableArray array];
    NSEnumerator   *en     = [fields objectEnumerator];
    NSString       *f;

    while ((f = [en nextObject]) != nil) {
        if ([f length] > 0)
            [tokens addObject:f];
    }

    /* Minimum viable line: iface proto src */
    if ([tokens count] < 3)
        return nil;

    NSString *src = [tokens objectAtIndex:2];

    /* IPv6: [addr]:port */
    if ([src hasPrefix:@"["]) {
        NSRange close = [src rangeOfString:@"]"];
        if (close.location == NSNotFound)
            return nil;
        return [src substringWithRange:NSMakeRange(1, close.location - 1)];
    }

    /* IPv4: addr:port — everything before the last colon */
    NSRange lastColon = [src rangeOfString:@":" options:NSBackwardsSearch];
    if (lastColon.location == NSNotFound)
        return nil;
    return [src substringToIndex:lastColon.location];
}

/* --- Monitoring --------------------------------------------------- */

/*
 * Poll the pf(4) state table via pfctl(8) and check each source IP
 * against the configured threshold, sending a remote syslog alert for
 * any IP that has exceeded it during this interval.
 */
- (void)checkStates
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/sbin/pfctl"];
    [task setArguments:[NSArray arrayWithObjects:@"-s", @"state", nil]];

    NSPipe *outPipe = [NSPipe pipe];
    [task setStandardOutput:outPipe];
    [task setStandardError:[NSFileHandle fileHandleWithNullDevice]];
    [task launch];

    NSData *data = [[outPipe fileHandleForReading] readDataToEndOfFile];
    [task waitUntilExit];
    [task release];

    NSString *output = [[[NSString alloc] initWithData:data
                                              encoding:NSUTF8StringEncoding]
                        autorelease];
    if (!output) {
        [pool drain];
        return;
    }

    NSArray      *lines = [output componentsSeparatedByString:@"\n"];
    NSEnumerator *en    = [lines objectEnumerator];
    NSString     *line;

    while ((line = [en nextObject]) != nil) {
        NSString *src = [self parseSrcFromLine:line];
        if (!src)
            continue;

        /* Skip loopback addresses */
        if ([src hasPrefix:@"127."] || [src isEqualToString:@"::1"])
            continue;

        NSNumber *count    = [_ipCounts objectForKey:src];
        int       newCount = count ? [count intValue] + 1 : 1;
        [_ipCounts setObject:[NSNumber numberWithInt:newCount] forKey:src];

        NSNumber *alerted = [_ipAlerted objectForKey:src];
        if (!alerted && newCount >= _threshold) {
            NSString *msg = [NSString stringWithFormat:
                @"Suspected DDoS attack from %@: "
                "%d connections within %d seconds",
                src, newCount, _interval];

            if (_verbose)
                NSLog(@"ddosshield: %@", msg);

            [self sendSyslog:msg];
            [_ipAlerted setObject:[NSNumber numberWithBool:YES] forKey:src];
        }
    }

    [pool drain];
}

/* Reset per-IP counters and alert flags at the end of each interval. */
- (void)resetTable
{
    [_ipCounts  removeAllObjects];
    [_ipAlerted removeAllObjects];
}

/* Main monitoring loop. */
- (void)run
{
    while (running) {
        [self checkStates];
        sleep((unsigned int)_interval);
        [self resetTable];
    }
}

@end

/* ------------------------------------------------------------------ */
/* Entry point                                                          */
/* ------------------------------------------------------------------ */

static void
usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [-v] [-c config] [-H host] [-p port]"
        " [-t threshold] [-i interval]\n",
        prog);
    exit(1);
}

int
main(int argc, const char *argv[])
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    DDOSShield *shield   = [[[DDOSShield alloc] init] autorelease];
    const char *conffile = "/etc/ddosshield.conf";

    /*
     * Two-pass argument handling:
     *   Pass 1 – scan for -c to find the config file to load.
     *   Pass 2 – getopt processes all flags; CLI values override config.
     * This ensures that -H/-p/-t/-i always win over config values
     * regardless of where -c appears on the command line.
     */

    /* Pass 1: locate -c */
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            conffile = argv[i + 1];
            break;
        }
    }
    [shield loadConfig:[NSString stringWithUTF8String:conffile]];

    /* Pass 2: apply all CLI flags (override any config-file values) */
    int ch;
    while ((ch = getopt(argc, (char *const *)argv, "vc:H:p:t:i:")) != -1) {
        switch (ch) {
        case 'v':
            [shield setVerbose:YES];
            break;
        case 'c':
            /* already handled in pass 1 */
            break;
        case 'H':
            [shield setRemoteHost:[NSString stringWithUTF8String:optarg]];
            break;
        case 'p':
            [shield setRemotePort:atoi(optarg)];
            break;
        case 't':
            [shield setThreshold:atoi(optarg)];
            break;
        case 'i':
            [shield setInterval:atoi(optarg)];
            break;
        default:
            usage(argv[0]);
        }
    }

    if (![shield remoteHost] || [[shield remoteHost] length] == 0) {
        fprintf(stderr,
            "ddosshield: remote_host not configured "
            "(use -H or set in %s)\n", conffile);
        exit(1);
    }
    if ([shield threshold] <= 0) {
        fprintf(stderr, "ddosshield: threshold must be a positive integer\n");
        exit(1);
    }
    if ([shield interval] <= 0) {
        fprintf(stderr, "ddosshield: interval must be a positive integer\n");
        exit(1);
    }

    if (![shield setupSocket])
        exit(1);

    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);

    /*
     * Restrict privileges with pledge(2) on OpenBSD.
     * "proc exec" is needed for NSTask; "inet" for UDP sendto.
     */
#ifdef __OpenBSD__
    if (pledge("stdio proc exec inet", NULL) == -1) {
        NSLog(@"ddosshield: pledge: %s", strerror(errno));
        exit(1);
    }
#endif

    if ([shield verbose])
        NSLog(@"ddosshield: started — remote=%@:%d threshold=%d interval=%ds",
            [shield remoteHost], [shield remotePort],
            [shield threshold], [shield interval]);

    [shield run];

    [pool drain];
    return 0;
}
