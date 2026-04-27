// DDOSShieldConfiguration.m

#import "DDOSShieldConfiguration.h"

@implementation DDOSShieldConfiguration

+ (instancetype)defaultConfiguration {
    DDOSShieldConfiguration *config = [[DDOSShieldConfiguration alloc] init];

    // -----------------------------------------------------------------------
    // Detection threshold — adjust to match expected legitimate traffic.
    // An IP with this many or more active pf state entries will be flagged.
    // -----------------------------------------------------------------------
    config.connectionThreshold = 100;

    // -----------------------------------------------------------------------
    // Firewall table name — must match the table defined in /etc/pf.conf.
    // -----------------------------------------------------------------------
    config.pfTableName = @"arbitraryblocks";

    // -----------------------------------------------------------------------
    // Replace this placeholder with the IP you never want to block (e.g. your
    // own management address).  Source IPs matching this value are skipped.
    // -----------------------------------------------------------------------
    config.whitelistIP = @"www.xxx.yyy.zzz";

    return config;
}

- (void)warnAboutPlaceholders {
    if ([_whitelistIP isEqualToString:@"www.xxx.yyy.zzz"]) {
        NSLog(@"ddos-shield: WARNING: whitelistIP is still set to the placeholder "
              @"'www.xxx.yyy.zzz'. No address is currently protected from being "
              @"blocked. Replace it with your management IP in "
              @"DDOSShieldConfiguration.m and rebuild to avoid accidentally "
              @"locking yourself out.");
    }
}

@end
