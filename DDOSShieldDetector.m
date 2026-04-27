// DDOSShieldDetector.m

#import "DDOSShieldDetector.h"

// Matches the source IPv4 address in a pfctl -s state output line.
//
// pfctl -s state produces lines of the form:
//   <iface> <proto> <src_ip>:<src_port> [(<nat_ip>:<port>)] -> <dst_ip>:<dst_port> ...
//
// The source IP immediately follows the protocol keyword and is separated
// from its port number by a colon or period.  Capturing only the first IP
// on the line (after the protocol) avoids counting destination addresses.
static NSString * const kStateSourceIPPattern =
    @"(?:tcp|udp|icmp|other)\\s+"
    @"((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    @"(?:\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})"
    @"[:.]";

@implementation DDOSShieldDetector {
    DDOSShieldConfiguration *_config;
    NSRegularExpression     *_sourceIPRegex;
}

- (instancetype)initWithConfiguration:(DDOSShieldConfiguration *)config {
    self = [super init];
    if (self) {
        _config = config;

        NSError *err = nil;
        _sourceIPRegex =
            [NSRegularExpression regularExpressionWithPattern:kStateSourceIPPattern
                                                      options:0
                                                        error:&err];
        if (!_sourceIPRegex) {
            NSLog(@"ddos-shield: internal error building source-IP regex: %@", err);
        }
    }
    return self;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

- (NSArray<NSString *> *)attackersInStateData:(NSString *)stateData {
    if (!_sourceIPRegex || stateData.length == 0) { return @[]; }

    NSMutableDictionary<NSString *, NSNumber *> *counts =
        [NSMutableDictionary dictionary];

    for (NSString *line in [stateData componentsSeparatedByString:@"\n"]) {
        if (line.length == 0) { continue; }

        NSTextCheckingResult *match =
            [_sourceIPRegex firstMatchInString:line
                                       options:0
                                         range:NSMakeRange(0, line.length)];
        if (!match) { continue; }

        NSString *ip = [line substringWithRange:[match rangeAtIndex:1]];

        // Skip the whitelisted address.
        if (_config.whitelistIP.length > 0 &&
            [ip isEqualToString:_config.whitelistIP]) {
            continue;
        }

        counts[ip] = @([counts[ip] integerValue] + 1);
    }

    NSMutableArray<NSString *> *result = [NSMutableArray array];
    for (NSString *ip in counts) {
        if ([counts[ip] integerValue] >= _config.connectionThreshold) {
            [result addObject:ip];
        }
    }
    return result;
}

- (NSArray<NSString *> *)detectAttackers {
    if (!_sourceIPRegex) { return @[]; }

    // Run pfctl -s state and capture its standard output.
    NSPipe *pipe = [NSPipe pipe];
    NSTask *task = [[NSTask alloc] init];
    task.launchPath     = @"/sbin/pfctl";
    task.arguments      = @[ @"-s", @"state" ];
    task.standardOutput = pipe;
    task.standardError  = [NSFileHandle fileHandleWithNullDevice];

    NSError *err = nil;
    if (![task launchAndReturnError:&err]) {
        NSLog(@"ddos-shield: pfctl -s state failed: %@", err);
        return @[];
    }

    NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
    [task waitUntilExit];

    NSString *stateData = [[NSString alloc] initWithData:data
                                                encoding:NSUTF8StringEncoding];
    if (!stateData) { return @[]; }

    return [self attackersInStateData:stateData];
}

@end
