// DDOSShieldConfiguration.h
// Edit the values in +defaultConfiguration to match your environment before
// building, or allocate a DDOSShieldConfiguration and set the properties at
// runtime.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DDOSShieldConfiguration : NSObject

// ---------------------------------------------------------------------------
// Detection settings
// ---------------------------------------------------------------------------

/// Number of active pf state entries from a single source IP required to
/// classify that IP as a DDoS attacker.
@property (nonatomic, assign) NSInteger connectionThreshold;

// ---------------------------------------------------------------------------
// Firewall settings
// ---------------------------------------------------------------------------

/// Name of the pf table to add blocked IPs to.
/// Must match the table defined in /etc/pf.conf.
@property (nonatomic, copy) NSString *pfTableName;

// ---------------------------------------------------------------------------
// Scanning settings
// ---------------------------------------------------------------------------

/// IP address to never block (your trusted management address).
/// Replace "www.xxx.yyy.zzz" with your real IP before deploying.
@property (nonatomic, copy) NSString *whitelistIP;

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Returns a configuration pre-filled with sensible defaults.
/// Edit these values to match your site before building.
+ (instancetype)defaultConfiguration;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Emit NSLog warnings for any settings that still contain placeholder values.
/// Call this once at program startup before performing any blocking actions.
- (void)warnAboutPlaceholders;

@end

NS_ASSUME_NONNULL_END
