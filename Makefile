# upcouch Makefile
CC = cc
CFLAGS = -std=c11 -Wall -Wextra -O2
LDFLAGS = -pthread -L/usr/local/lib
LIBS = -lcurl -lcrypto -lpthread
INCLUDES = -I/usr/local/include
TARGET = upcouch
SRC = upcouch.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) $(LDFLAGS) $(LIBS) -o $(TARGET)

clean:
	rm -f $(TARGET)

install:
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)
