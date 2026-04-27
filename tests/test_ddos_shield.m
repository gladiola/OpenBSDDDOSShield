// tests/test_ddos_shield.m

#import <Foundation/Foundation.h>
#import "../DDOSShieldConfiguration.h"
#import "../DDOSShieldDetector.h"
#import "../DDOSShieldBlocker.h"

/* ── Minimal test framework ─────────────────────────────────────────────── */

static int g_passed = 0;
static int g_failed = 0;

#define ASSERT(desc, expr)                                               \
    do {                                                                 \
        if (expr) {                                                      \
            g_passed++;                                                  \
            fprintf(stdout, "PASS: %s\n", (desc));                      \
        } else {                                                         \
            g_failed++;                                                  \
            fprintf(stderr, "FAIL: %s  (line %d)\n", (desc), __LINE__); \
        }                                                                \
    } while (0)

/* ── Helpers ────────────────────────────────────────────────────────────── */

/* Build a synthetic pfctl -s state line for a given source and destination. */
static NSString *stateLine(NSString *srcIP, NSUInteger srcPort,
                            NSString *dstIP, NSUInteger dstPort)
{
    return [NSString stringWithFormat:
        @"em0 tcp %@:%lu -> %@:%lu       ESTABLISHED:ESTABLISHED",
        srcIP, (unsigned long)srcPort,
        dstIP, (unsigned long)dstPort];
}

/* ── DDOSShieldConfiguration tests ─────────────────────────────────────── */

static void testConfigurationDefaults(void)
{
    DDOSShieldConfiguration *c = [DDOSShieldConfiguration defaultConfiguration];

    ASSERT("config: connectionThreshold is 100",
           c.connectionThreshold == 100);
    ASSERT("config: pfTableName is non-empty",
           c.pfTableName.length > 0);
    ASSERT("config: pfTableName is arbitraryblocks",
           [c.pfTableName isEqualToString:@"arbitraryblocks"]);
    ASSERT("config: whitelistIP is non-empty (placeholder set)",
           c.whitelistIP.length > 0);
}

/* ── DDOSShieldDetector tests ───────────────────────────────────────────── */

static void testDetectorFindsSingleAttacker(void)
{
    DDOSShieldConfiguration *config = [DDOSShieldConfiguration defaultConfiguration];
    config.connectionThreshold = 3;
    config.whitelistIP = @"";

    /* 1.2.3.4 appears 3 times — exactly at threshold */
    NSMutableString *data = [NSMutableString string];
    for (NSUInteger i = 0; i < 3; i++) {
        [data appendFormat:@"%@\n",
            stateLine(@"1.2.3.4", 10000 + i, @"5.6.7.8", 80)];
    }

    DDOSShieldDetector *detector =
        [[DDOSShieldDetector alloc] initWithConfiguration:config];
    NSArray<NSString *> *attackers = [detector attackersInStateData:data];

    ASSERT("detector single: IP at threshold detected",
           [attackers containsObject:@"1.2.3.4"]);
    ASSERT("detector single: exactly one attacker returned",
           attackers.count == 1);
}

static void testDetectorIgnoresBelowThreshold(void)
{
    DDOSShieldConfiguration *config = [DDOSShieldConfiguration defaultConfiguration];
    config.connectionThreshold = 5;
    config.whitelistIP = @"";

    /* 1.2.3.4 appears 4 times — one below threshold */
    NSMutableString *data = [NSMutableString string];
    for (NSUInteger i = 0; i < 4; i++) {
        [data appendFormat:@"%@\n",
            stateLine(@"1.2.3.4", 10000 + i, @"5.6.7.8", 80)];
    }

    DDOSShieldDetector *detector =
        [[DDOSShieldDetector alloc] initWithConfiguration:config];
    NSArray<NSString *> *attackers = [detector attackersInStateData:data];

    ASSERT("detector below threshold: IP not flagged", attackers.count == 0);
}

static void testDetectorMultipleAttackers(void)
{
    DDOSShieldConfiguration *config = [DDOSShieldConfiguration defaultConfiguration];
    config.connectionThreshold = 2;
    config.whitelistIP = @"";

    /* 1.2.3.4 → 3 entries (above), 9.9.9.9 → 2 entries (at), 5.5.5.5 → 1 (below) */
    NSMutableString *data = [NSMutableString string];
    for (NSUInteger i = 0; i < 3; i++)
        [data appendFormat:@"%@\n", stateLine(@"1.2.3.4", 10000 + i, @"5.6.7.8", 80)];
    for (NSUInteger i = 0; i < 2; i++)
        [data appendFormat:@"%@\n", stateLine(@"9.9.9.9", 20000 + i, @"5.6.7.8", 80)];
    for (NSUInteger i = 0; i < 1; i++)
        [data appendFormat:@"%@\n", stateLine(@"5.5.5.5", 30000 + i, @"5.6.7.8", 80)];

    DDOSShieldDetector *detector =
        [[DDOSShieldDetector alloc] initWithConfiguration:config];
    NSArray<NSString *> *attackers = [detector attackersInStateData:data];

    ASSERT("detector multi: 1.2.3.4 detected",
           [attackers containsObject:@"1.2.3.4"]);
    ASSERT("detector multi: 9.9.9.9 detected",
           [attackers containsObject:@"9.9.9.9"]);
    ASSERT("detector multi: 5.5.5.5 not detected",
           ![attackers containsObject:@"5.5.5.5"]);
    ASSERT("detector multi: exactly 2 attackers returned",
           attackers.count == 2);
}

static void testDetectorRespectsWhitelist(void)
{
    DDOSShieldConfiguration *config = [DDOSShieldConfiguration defaultConfiguration];
    config.connectionThreshold = 1;
    config.whitelistIP = @"1.2.3.4";

    NSMutableString *data = [NSMutableString string];
    [data appendFormat:@"%@\n", stateLine(@"1.2.3.4", 10001, @"5.6.7.8", 80)];
    [data appendFormat:@"%@\n", stateLine(@"9.9.9.9", 20001, @"5.6.7.8", 80)];

    DDOSShieldDetector *detector =
        [[DDOSShieldDetector alloc] initWithConfiguration:config];
    NSArray<NSString *> *attackers = [detector attackersInStateData:data];

    ASSERT("detector whitelist: whitelisted IP excluded",
           ![attackers containsObject:@"1.2.3.4"]);
    ASSERT("detector whitelist: non-whitelisted IP detected",
           [attackers containsObject:@"9.9.9.9"]);
}

static void testDetectorEmptyInput(void)
{
    DDOSShieldConfiguration *config = [DDOSShieldConfiguration defaultConfiguration];
    config.connectionThreshold = 1;
    config.whitelistIP = @"";

    DDOSShieldDetector *detector =
        [[DDOSShieldDetector alloc] initWithConfiguration:config];
    NSArray<NSString *> *attackers = [detector attackersInStateData:@""];

    ASSERT("detector empty: returns empty array", attackers.count == 0);
}

static void testDetectorUDPStates(void)
{
    DDOSShieldConfiguration *config = [DDOSShieldConfiguration defaultConfiguration];
    config.connectionThreshold = 2;
    config.whitelistIP = @"";

    /* UDP state lines — the parser must handle them the same as TCP. */
    NSMutableString *data = [NSMutableString string];
    for (NSUInteger i = 0; i < 2; i++) {
        [data appendFormat:@"em0 udp 7.7.7.7:%lu -> 5.6.7.8:53       MULTIPLE:SINGLE\n",
            40000 + i];
    }

    DDOSShieldDetector *detector =
        [[DDOSShieldDetector alloc] initWithConfiguration:config];
    NSArray<NSString *> *attackers = [detector attackersInStateData:data];

    ASSERT("detector UDP: attacker on UDP states detected",
           [attackers containsObject:@"7.7.7.7"]);
}

static void testDetectorNonStateLinesIgnored(void)
{
    /* Lines without a protocol keyword before an IP should be ignored. */
    DDOSShieldConfiguration *config = [DDOSShieldConfiguration defaultConfiguration];
    config.connectionThreshold = 1;
    config.whitelistIP = @"";

    NSString *data =
        @"No ALTQ support in kernel\n"
        @"ALTQ related functions disabled\n"
        @"Informational line mentioning IP 1.2.3.4\n";

    DDOSShieldDetector *detector =
        [[DDOSShieldDetector alloc] initWithConfiguration:config];
    NSArray<NSString *> *attackers = [detector attackersInStateData:data];

    ASSERT("detector non-state: informational lines ignored",
           attackers.count == 0);
}

static void testDetectorDestinationNotCounted(void)
{
    /* The destination IP (5.6.7.8 here) must not be counted as a source. */
    DDOSShieldConfiguration *config = [DDOSShieldConfiguration defaultConfiguration];
    config.connectionThreshold = 1;
    config.whitelistIP = @"";

    /* Single state entry — only the source (1.2.3.4) should be counted. */
    NSString *data = [NSString stringWithFormat:@"%@\n",
        stateLine(@"1.2.3.4", 10001, @"5.6.7.8", 80)];

    DDOSShieldDetector *detector =
        [[DDOSShieldDetector alloc] initWithConfiguration:config];
    NSArray<NSString *> *attackers = [detector attackersInStateData:data];

    ASSERT("detector dst not counted: source IP detected",
           [attackers containsObject:@"1.2.3.4"]);
    ASSERT("detector dst not counted: destination IP not counted as attacker",
           ![attackers containsObject:@"5.6.7.8"]);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        testConfigurationDefaults();
        testDetectorFindsSingleAttacker();
        testDetectorIgnoresBelowThreshold();
        testDetectorMultipleAttackers();
        testDetectorRespectsWhitelist();
        testDetectorEmptyInput();
        testDetectorUDPStates();
        testDetectorNonStateLinesIgnored();
        testDetectorDestinationNotCounted();

        fprintf(stdout, "\n%d passed, %d failed\n", g_passed, g_failed);
    }
    return g_failed > 0 ? 1 : 0;
}
