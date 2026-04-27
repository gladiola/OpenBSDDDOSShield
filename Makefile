CC     = cc
CFLAGS = -isystem /usr/local/include \
         -I/usr/local/include/GNUstep \
         -fobjc-runtime=gnustep-2.0 \
         -fblocks
LDFLAGS = -L/usr/local/lib \
          -lgnustep-base -lobjc2 -lpthread

TARGET = ddosshield
SRC    = ddosshield.m

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/sbin/$(TARGET)

clean:
	rm -f $(TARGET)
# Build flags come from gnustep-config so they work on any GNUstep platform
# (OpenBSD with pkg_add gnustep-make gnustep-base libobjc2, or Linux).
CC      = cc
CFLAGS  = $(shell gnustep-config --objc-flags) -fobjc-arc
LDFLAGS = $(shell gnustep-config --base-libs)

TARGET = ddos-shield
SRCS   = main.m \
         DDOSShieldConfiguration.m \
         DDOSShieldDetector.m \
         DDOSShieldBlocker.m

TEST_TARGET = tests/test_ddos_shield
TEST_SRCS   = tests/test_ddos_shield.m \
              DDOSShieldConfiguration.m \
              DDOSShieldDetector.m \
              DDOSShieldBlocker.m

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SRCS)
	$(CC) $(CFLAGS) -o $(TEST_TARGET) $(TEST_SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TEST_TARGET)

install:
	install -m 0755 $(TARGET) /usr/local/sbin/ddos-shield

.PHONY: all test clean install
