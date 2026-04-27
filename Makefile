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
