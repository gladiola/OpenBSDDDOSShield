// DDOSShieldDetector.h
// Reads the live pf state table (via pfctl -s state), counts active
// connections per source IP, and returns any IP whose count meets or
// exceeds the configured connectionThreshold.

#import <Foundation/Foundation.h>
#import "DDOSShieldConfiguration.h"

NS_ASSUME_NONNULL_BEGIN

@interface DDOSShieldDetector : NSObject

- (instancetype)initWithConfiguration:(DDOSShieldConfiguration *)config;

/// Run pfctl -s state, parse the output, and return IPs whose active
/// connection count meets or exceeds config.connectionThreshold.
/// The whitelist IP is excluded.
/// Requires root (pfctl reads kernel state).
/// @return  A (possibly empty) array of NSString IPv4 addresses.
- (NSArray<NSString *> *)detectAttackers;

/// Parse raw pfctl -s state output and return IPs above threshold.
/// Source IPs are counted per state table entry.  The whitelist IP is
/// excluded.  Exposed for unit testing without requiring root or pfctl.
///
/// @param stateData  The full text output of pfctl -s state.
/// @return           A (possibly empty) array of NSString IPv4 addresses.
- (NSArray<NSString *> *)attackersInStateData:(NSString *)stateData;

@end

NS_ASSUME_NONNULL_END
