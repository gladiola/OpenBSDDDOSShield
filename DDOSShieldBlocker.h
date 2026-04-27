// DDOSShieldBlocker.h
// Handles detection logging and optional direct pf blocking.
//
//  • logDetection:  — logs "detected from <IP>" to the local syslog at
//    daemon.warning priority via logger(1) with tag "DDOSShield".  Always
//    called regardless of HBP presence so that HBP's --monitor-ddos can
//    consume the message from /var/log/daemon.
//
//  • blockIP:       — adds <IP> directly to the live pf table via pfctl.
//    Only call this when HBP is not present; when HBP is present it reads
//    /var/log/daemon and manages all pf table updates itself.

#import <Foundation/Foundation.h>
#import "DDOSShieldConfiguration.h"

NS_ASSUME_NONNULL_BEGIN

@interface DDOSShieldBlocker : NSObject

- (instancetype)initWithConfiguration:(DDOSShieldConfiguration *)config;

/// Log a detection event to local syslog (daemon.warning) using logger(1)
/// with tag "DDOSShield".  The resulting line:
///   "MMM dd HH:mm:ss hostname DDOSShield[pid]: detected from <ip>"
/// matches the pattern HBP's --monitor-ddos scans for.
- (void)logDetection:(NSString *)ip;

/// Add @a ip directly to the live pf block table via pfctl.
/// Only call this when HBP is absent; when HBP is present, HBP manages
/// all pf table updates after reading the syslog entry.
/// Requires root.
- (void)blockIP:(NSString *)ip;

@end

NS_ASSUME_NONNULL_END
