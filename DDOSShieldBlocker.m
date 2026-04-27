// DDOSShieldBlocker.m

#import "DDOSShieldBlocker.h"

@implementation DDOSShieldBlocker {
    DDOSShieldConfiguration *_config;
}

- (instancetype)initWithConfiguration:(DDOSShieldConfiguration *)config {
    self = [super init];
    if (self) {
        _config = config;
    }
    return self;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

- (void)runTask:(NSString *)launchPath arguments:(NSArray<NSString *> *)args {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = launchPath;
    task.arguments  = args;
    NSError *err = nil;
    if (![task launchAndReturnError:&err]) {
        NSLog(@"ddos-shield: %@ failed: %@", launchPath.lastPathComponent, err);
    } else {
        [task waitUntilExit];
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

- (void)logDetection:(NSString *)ip {
    // Use logger(1) with -t DDOSShield so the syslog tag field reads
    // "DDOSShield", producing lines like:
    //   "Apr 27 15:30:45 hostname DDOSShield[1234]: detected from 1.2.3.4"
    // This matches the pattern HBP's --monitor-ddos scans for in /var/log/daemon.
    [self runTask:@"/usr/bin/logger"
        arguments:@[ @"-t", @"DDOSShield",
                     @"-p", @"daemon.warning",
                     [NSString stringWithFormat:@"detected from %@", ip] ]];
}

- (void)blockIP:(NSString *)ip {
    [self runTask:@"/sbin/pfctl"
        arguments:@[ @"-t", _config.pfTableName,
                     @"-T", @"add",
                     ip ]];
}

@end
