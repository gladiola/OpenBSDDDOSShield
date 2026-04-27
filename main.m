// main.m
// ddos-shield — OpenBSD DDoS detection with HBP-aware blocking.
//
// Reads the live pf state table, identifies source IPs with a high number of
// active connections, and handles them in one of two modes:
//
//   HBP present (/usr/local/sbin/pf-blocker is executable):
//     Logs each attacker to syslog (daemon.warning, tag "DDOSShield") and
//     exits.  HBP's --monitor-ddos cron entry picks up the log line and
//     handles all blocking, ledger management, and expiry.
//
//   HBP absent:
//     Logs each attacker to syslog (for auditability) and also adds the IP
//     directly to the pf block table via pfctl.
//
// Add to root's crontab:
//
//   # When HBP is present (--monitor-ddos is already in HBP's crontab):
//   */5 * * * * /usr/local/sbin/ddos-shield
//
//   # When HBP is absent (ddos-shield handles detection and direct blocking):
//   */5 * * * * /usr/local/sbin/ddos-shield

#import <Foundation/Foundation.h>
#include <unistd.h>   /* access(2) */
#import "DDOSShieldConfiguration.h"
#import "DDOSShieldDetector.h"
#import "DDOSShieldBlocker.h"

/// Returns YES when HBP (pf-blocker) is installed and executable on this system.
static BOOL hbpIsPresent(void) {
    return access("/usr/local/sbin/pf-blocker", X_OK) == 0;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        BOOL hbpPresent = hbpIsPresent();

        DDOSShieldConfiguration *config =
            [DDOSShieldConfiguration defaultConfiguration];
        [config warnAboutPlaceholders];

        DDOSShieldDetector *detector =
            [[DDOSShieldDetector alloc] initWithConfiguration:config];
        NSArray<NSString *> *attackers = [detector detectAttackers];

        if (attackers.count == 0) {
            return 0;
        }

        DDOSShieldBlocker *blocker =
            [[DDOSShieldBlocker alloc] initWithConfiguration:config];

        for (NSString *ip in attackers) {
            // Always log so HBP's --monitor-ddos (or any syslog consumer)
            // can react, regardless of whether HBP manages the blocking.
            [blocker logDetection:ip];

            // Only touch pf directly when HBP is not present.  When HBP is
            // present it reads /var/log/daemon and calls pfctl itself, so
            // doing it here too would conflict with HBP's table management.
            if (!hbpPresent) {
                [blocker blockIP:ip];
            }
        }
    }
    return 0;
}
